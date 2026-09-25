# hubble/cloud_api.py
from __future__ import annotations

import base64
import time
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Any

import httpx

from .errors import (
    APITimeout,
    BackendError,
    NetworkError,
    PermissionDeniedError,
    raise_for_response,
)
from .packets import AesEaxPacket, EncryptedPacket

# The decode endpoint rejects a request carrying more advertisements than this.
DECODE_BATCH_LIMIT = 25
# ...and any advertisement received longer ago, or further ahead, than these.
DECODE_MAX_AGE_S = 72 * 3600
DECODE_MAX_FUTURE_S = 2 * 3600
# Default values for location metadata when ingesting packets
# These are placeholders when actual accuracy/altitude data is unavailable
# (the decode endpoint requires a location, so a packet without one gets 0,0).
_PLACEHOLDER_COORD = 0.0
DEFAULT_HORIZONTAL_ACCURACY_M = 0.0
DEFAULT_ALTITUDE_M = 0.0
DEFAULT_VERTICAL_ACCURACY_M = 0.0


@dataclass(frozen=True)
class Environment:
    name: str
    url: str


@dataclass(frozen=True)
class Credentials:
    org_id: str
    api_token: str


_ENVIRONMENTS = [
    Environment("PROD", "https://api.hubble.com"),
    Environment("TESTING", "https://api-testing.hubblenetwork.io"),
]


def _auth_headers(api_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _list_devices_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}/devices"


def _register_device_endpoint(credentials: Credentials) -> str:
    return f"/v2/org/{credentials.org_id}/devices"


def _retrieve_org_packets_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}/packets"


def _ingest_packets_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}/packets"


def _decode_packets_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}/packets/decode"


def _device_endpoint(credentials: Credentials, device_id: str) -> str:
    return f"/org/{credentials.org_id}/devices/{device_id}"


def _retrieve_org_metadata_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}"


def _validate_key_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}/check"


def _device_metrics_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}/device_metrics"


def cloud_request(
    *,
    method: str,
    path: str,
    env: Environment,
    credentials: Credentials | None = None,
    json: Any = None,
    timeout_s: float = 10.0,
    params: MutableMapping[str, Any] | None = None,
    continuation_token: str | None = None,
) -> Any:
    """
    Make a single HTTP request to the Hubble Cloud API and return parsed JSON.

    - `method`: "GET", "POST", etc.
    - `path`: endpoint path (e.g., "/devices" or "orgs/{id}/devices")
    - `credentials`: Credentials to use for this call
    - `env`: Environment to call into (typically prod or testing)
    - `json`: request JSON body (for POST/PUT/PATCH)
    - `timeout_s`: request timeout in seconds
    - `params`: optional HTTP request parameters
    """
    url = f"{env.url.rstrip('/')}/api/{path.lstrip('/')}"

    # headers
    headers: MutableMapping[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if credentials:
        headers["Authorization"] = f"Bearer {credentials.api_token}"
    if continuation_token:
        headers["Continuation-Token"] = continuation_token
    try:
        with httpx.Client(timeout=timeout_s) as client:
            resp = client.request(
                method.upper(), url, params=params, headers=headers, json=json
            )
    except httpx.TimeoutException as e:
        raise APITimeout(f"Request timed out: {method} {url}") from e
    except httpx.HTTPError as e:
        raise NetworkError(f"Network error: {method} {url}: {e}") from e

    if resp.is_error:
        body = None
        try:
            body = resp.json()
        except ValueError:  # response body may not be JSON; fall back to raw text
            body = resp.text
        raise_for_response(resp.status_code, body=body)

    # Parse JSON body
    try:
        continuation_token = (
            resp.headers.get("Continuation-Token", None)
        )
        return (resp.json(), continuation_token)
    except ValueError as e:
        # Server said "application/json" but body isn't JSON
        raise BackendError(f"Non-JSON response from {url}") from e


def get_env_from_credentials(credentials: Credentials) -> Environment | None:
    for env in _ENVIRONMENTS:
        try:
            # If this call fails then we know we don't have the
            # credentials for this environment
            cloud_request(
                method="GET",
                path=_validate_key_endpoint(credentials),
                credentials=credentials,
                env=env,
            )
            return env
        except BackendError:  # cloud_request() only ever raises BackendError subclasses
            pass
    return None


def register_device(
    *,
    credentials: Credentials,
    env: Environment,
    encryption: str = "AES-256-CTR",
    counter_source: str | None = None,
    period_in_seconds: int | None = None,
    period_exponent: int | None = None,
    tags: dict[str, str] | None = None,
) -> Any:
    """Create a new device and return it.

    Args:
        tags: Optional custom tags for the new device. The Cloud API accepts a
            per-device tags map in a list matching ``n_devices``; when provided
            here it is sent as a single-element list.
    """
    data: dict = {
        "n_devices": 1,
        "encryption": encryption or "AES-256-CTR",
    }
    if counter_source is not None:
        eid_rotation: dict = {"counter_source": counter_source}
        if period_in_seconds is not None:
            eid_rotation["period_in_seconds"] = period_in_seconds
        if period_exponent is not None:
            eid_rotation["period_exponent"] = period_exponent
        data["eid_rotation"] = eid_rotation
    if tags is not None:
        data["tags"] = [tags]
    return cloud_request(
        method="POST",
        env=env,
        path=_register_device_endpoint(credentials),
        credentials=credentials,
        json=data,
    )[0]


def update_device(
    *,
    credentials: Credentials,
    env: Environment,
    name: str,
    device_id: str,
    tags: dict[str, str] | None = None,
) -> Any:
    """Update a device.

    ``set_tags`` is a full replace on the Cloud API. Only include it when the
    caller explicitly passes ``tags``; an empty ``set_tags`` would wipe existing
    tags (including ones applied at registration).
    """
    data: dict = {
        "set_name": name,
    }
    if tags is not None:
        data["set_tags"] = tags
    return cloud_request(
        method="PATCH",
        env=env,
        path=_device_endpoint(credentials, device_id),
        credentials=credentials,
        json=data,
    )[0]


def delete_device(
    *,
    credentials: Credentials,
    env: Environment,
    device_id: str,
) -> None:
    """Delete a device."""
    cloud_request(
        method="DELETE",
        path=_device_endpoint(credentials, device_id),
        credentials=credentials,
        env=env,
    )


def list_devices(
    *, credentials: Credentials, env: Environment, continuation_token=None
) -> list[Any]:
    """
    List devices for the org (keys typically omitted).

    Returns:
        json response from server

    """
    return cloud_request(
        method="GET",
        env=env,
        path=_list_devices_endpoint(credentials),
        credentials=credentials,
        continuation_token=continuation_token,
    )


def retrieve_packets(
    *,
    credentials: Credentials,
    env: Environment,
    device_id: str,
    days: int = 7,
    continuation_token=None,
) -> Any:
    """Fetch decrypted packets for a device."""
    params = {"start": (int(time.time()) - (days * 24 * 60 * 60))}
    if device_id:
        params["device_id"] = device_id

    return cloud_request(
        method="GET",
        env=env,
        path=_retrieve_org_packets_endpoint(credentials),
        credentials=credentials,
        params=params,
        continuation_token=continuation_token,
    )


def ingest_packet(
    *,
    credentials: Credentials,
    env: Environment,
    packet: EncryptedPacket,
) -> Any:
    body = {
        "ble_locations": [
            {
                "location": {
                    "latitude": packet.location.lat,
                    "longitude": packet.location.lon,
                    "timestamp": packet.timestamp,
                    "horizontal_accuracy": DEFAULT_HORIZONTAL_ACCURACY_M,
                    "altitude": DEFAULT_ALTITUDE_M,
                    "vertical_accuracy": DEFAULT_VERTICAL_ACCURACY_M,
                },
                "adv": [
                    {
                        "payload": base64.b64encode(packet.payload).decode("utf-8"),
                        "rssi": packet.rssi,
                        "timestamp": packet.timestamp,
                    }
                ],
            }
        ]
    }
    return cloud_request(
        method="POST",
        env=env,
        path=_ingest_packets_endpoint(credentials),
        credentials=credentials,
        json=body,
    )[0]


def get_device(
    *,
    credentials: Credentials,
    env: Environment,
    device_id: str,
) -> Any:
    """Fetch one registered device. Raises ``NotFoundError`` if it is not in the org."""
    return cloud_request(
        method="GET",
        env=env,
        path=_device_endpoint(credentials, device_id),
        credentials=credentials,
    )[0]


def advertisement_bytes(packet: EncryptedPacket | AesEaxPacket) -> bytes:
    """Return the raw BLE service-data bytes the cloud needs to decode ``packet``.

    ``EncryptedPacket.payload`` is already the whole advertisement. For
    ``AesEaxPacket`` the bytes captured by the BLE parser (``raw``) are used;
    a hand-built packet without them is re-serialized from its parsed fields,
    with the two reserved low bits of the first byte set to zero.
    """
    if isinstance(packet, AesEaxPacket):
        if packet.raw is not None:
            return packet.raw
        return (
            bytes([(packet.protocol_version & 0x3F) << 2])
            + packet.nonce_salt
            + packet.eid.to_bytes(8, "little")
            + packet.payload
            + packet.auth_tag
        )
    if isinstance(packet, EncryptedPacket):
        return packet.payload
    raise ValueError(
        f"cannot decode {type(packet).__name__} in the cloud; only "
        "EncryptedPacket (AES-CTR) and AesEaxPacket (AES-EAX) are supported"
    )


def decode_window_ok(timestamp: float, *, now: float | None = None) -> bool:
    """True if the decode endpoint will accept a packet received at ``timestamp``."""
    now = time.time() if now is None else now
    return now - DECODE_MAX_AGE_S < timestamp <= now + DECODE_MAX_FUTURE_S


def packet_to_advertisement(packet: EncryptedPacket | AesEaxPacket) -> dict:
    """Build one entry of the decode endpoint's ``advertisements`` list."""
    ts = float(packet.timestamp)
    loc = packet.location
    return {
        "payload": base64.b64encode(advertisement_bytes(packet)).decode("ascii"),
        "rssi": int(packet.rssi),
        "timestamp": ts,
        "location": {
            "latitude": float(loc.lat) if loc else _PLACEHOLDER_COORD,
            "longitude": float(loc.lon) if loc else _PLACEHOLDER_COORD,
            "altitude": float(loc.alt_m)
            if loc and loc.alt_m is not None
            else DEFAULT_ALTITUDE_M,
            "horizontal_accuracy": DEFAULT_HORIZONTAL_ACCURACY_M,
            "vertical_accuracy": DEFAULT_VERTICAL_ACCURACY_M,
            "timestamp": ts,
        },
    }


def decode_packets(
    *,
    credentials: Credentials,
    env: Environment,
    advertisements: list[dict],
    metadata: dict[str, str] | None = None,
    timeout_s: float = 10.0,
) -> list[dict]:
    """Decode up to ``DECODE_BATCH_LIMIT`` advertisements in one request.

    ``advertisements`` are wire-format dicts (see :func:`packet_to_advertisement`).
    Returns the response's ``packets`` list: one entry per advertisement the
    cloud could decrypt for this org, each echoing its input under
    ``advertisement.payload``. Advertisements that do not decrypt are omitted.

    The endpoint also stores what it decodes, exactly as ingestion would, so
    do not also send the same packet to :func:`ingest_packet`.

    Raises ``ValueError`` for an empty or oversized batch and
    ``PermissionDeniedError`` when the API key lacks the ``read-packets`` scope.
    """
    if not advertisements:
        raise ValueError("advertisements must not be empty")
    if len(advertisements) > DECODE_BATCH_LIMIT:
        raise ValueError(
            f"at most {DECODE_BATCH_LIMIT} advertisements per request, "
            f"got {len(advertisements)}"
        )
    body: dict[str, Any] = {"advertisements": list(advertisements)}
    if metadata:
        body["metadata"] = metadata
    try:
        resp = cloud_request(
            method="POST",
            env=env,
            path=_decode_packets_endpoint(credentials),
            credentials=credentials,
            json=body,
            timeout_s=timeout_s,
        )[0]
    except PermissionDeniedError as e:
        raise PermissionDeniedError(
            "The API key lacks the 'read-packets' scope needed to decode "
            "packets, or belongs to a different organization. Use a key from "
            f"this org with that scope. ({e})"
        ) from e
    if not isinstance(resp, dict):
        raise BackendError("Unexpected response from the packet decode endpoint")
    return resp.get("packets") or []


def retrieve_org_metadata(
    *,
    credentials: Credentials,
    env: Environment,
) -> Any:
    """
    Get organizational metadata

    Returns:
        json response from server

    """
    return cloud_request(
        method="GET",
        env=env,
        path=_retrieve_org_metadata_endpoint(credentials),
        credentials=credentials,
    )[0]


def device_metrics(
    *,
    credentials: Credentials,
    env: Environment,
    days_back: int = 1,
    time_interval: str | None = None,
) -> dict:
    """Fetch device metrics (registered, active, never-active counts)."""
    params: MutableMapping[str, Any] = {
        "daysBack": days_back,
    }
    if time_interval:
        params["timeInterval"] = time_interval
    return cloud_request(
        method="GET",
        env=env,
        path=_device_metrics_endpoint(credentials),
        credentials=credentials,
        params=params,
    )[0]
