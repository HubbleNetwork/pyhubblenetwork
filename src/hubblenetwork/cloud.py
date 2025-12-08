# hubble/cloud_api.py
from __future__ import annotations
from dataclasses import dataclass
import httpx
import time
import base64
from typing import Any, Optional
from collections.abc import MutableMapping
from .packets import EncryptedPacket
from .errors import (
    BackendError,
    NetworkError,
    APITimeout,
    raise_for_response,
)


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


def _retrieve_org_metadata_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}"


def _validate_key_endpoint(credentials: Credentials) -> str:
    return f"/org/{credentials.org_id}/check"


def cloud_request(
    *,
    method: str,
    path: str,
    env: Environment,
    credentials: Optional[Credentials] = None,
    json: Any = None,
    timeout_s: float = 10.0,
    params: Optional[MutableMapping[str, Any]] = None,
    continuation_token: Optional[str] = None,
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
        except Exception:
            body = resp.text
        raise_for_response(resp.status_code, body=body)

    # Parse JSON body
    try:
        continuation_token = (
            resp.headers["Continuation-Token"]
            if "Continuation-Token" in resp.headers
            else None
        )
        return (resp.json(), continuation_token)
    except ValueError as e:
        # Server said "application/json" but body isn't JSON
        raise BackendError(f"Non-JSON response from {url}") from e


def get_env_from_credentials(credentials: Credentials) -> Optional[Environment]:
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
        except Exception:
            pass
    return None


def register_device(
    *, credentials: Credentials, env: Environment, encryption: str = "AES-256-CTR"
) -> Any:
    """Create a new device and return it."""
    data = {
        "n_devices": 1,
        "encryption": "AES-256-CTR" if not encryption else encryption,
    }
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
) -> Any:
    """Update a device."""
    data = {
        "set_name": name,
        "set_tags": {},
    }
    return cloud_request(
        method="PATCH",
        env=env,
        path=_update_device_endpoint(credentials, device_id),
        credentials=credentials,
        json=data,
    )[0]


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
                    "horizontal_accuracy": 42,
                    "altitude": 42,
                    "vertical_accuracy": 42,
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
