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
    raise_for_response,
)
from .packets import EncryptedPacket

# Default values for location metadata when ingesting packets
# These are placeholders when actual accuracy/altitude data is unavailable
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


def _update_device_endpoint(credentials: Credentials, device_id: str) -> str:
    return f"/org/{credentials.org_id}/devices/{device_id}"


def _delete_device_endpoint(credentials: Credentials, device_id: str) -> str:
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
        path=_update_device_endpoint(credentials, device_id),
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
        path=_delete_device_endpoint(credentials, device_id),
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
