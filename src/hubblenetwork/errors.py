"""
Exception hierarchy for the Hubble Python SDK.

Usage:
    from .errors import (
        BackendError, ServerError, ScanError, DecryptionError,
        ValidationError, ScanError, DecryptionError, raise_for_response,
    )
"""

from __future__ import annotations
from typing import Any, Optional


# ----- Base classes ---------------------------------------------------------


class HubbleError(Exception):
    """Base exception for all SDK errors."""


# Cloud/backend-facing errors
class BackendError(HubbleError):
    """Generic back end error from the Hubble Cloud API"""


class RequestError(BackendError):
    """Bad request error from the Hubble Cloud API."""


class InternalServerError(BackendError):
    """Server side error from the Hubble Cloud API."""


class NetworkError(BackendError):
    """Transport-layer failures (DNS, connection reset, etc.)."""


class APITimeout(BackendError):
    """The API call exceeded its allowed timeout."""


class InvalidCredentialsError(BackendError):
    """Invalid credentials passed in"""


# Request/response semantics
class ValidationError(BackendError):
    """The request was invalid (schema/semantics)."""


# Local/host-side errors
class ScanError(HubbleError):
    """BLE scanning failed locally (adapter/permissions/OS/driver)."""


class DecryptionError(HubbleError):
    """Local decryption failed (bad key, corrupt packet, etc.)."""


class BleError(HubbleError):
    """BLE operation failed (connection, GATT read/write, etc.)."""

    def __init__(self, message: str, att_error_code: Optional[int] = None):
        super().__init__(message)
        self.att_error_code = att_error_code

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        result: dict[str, Any] = {
            "message": str(self),
        }
        if self.att_error_code is not None:
            result["att_error_code"] = self.att_error_code
            result["att_error_name"] = ATT_ERROR_NAMES.get(
                self.att_error_code,
                f"Unknown ATT Error (0x{self.att_error_code:02X})"
            )
        return result


# ATT Error Code Constants (from Bluetooth Core Specification)
ATT_INVALID_ATTRIBUTE_LENGTH = 0x0D  # Invalid Attribute Value Length
ATT_INSUFFICIENT_ENCRYPTION = 0x0F   # Insufficient Encryption
ATT_INVALID_POOL_SIZE = 0x84         # Application Error: Invalid Pool Size
ATT_INVALID_ROTATION_PERIOD = 0x85   # Application Error: Invalid Rotation Period
ATT_INVALID_EID_TYPE = 0x86          # Application Error: Invalid EID Type
ATT_INVALID_EID_PARAMETER = 0x87     # Application Error: Invalid EID Parameter

# Human-readable names for ATT error codes
ATT_ERROR_NAMES = {
    0x0D: "Invalid Attribute Value Length",
    0x0F: "Insufficient Encryption",
    0x84: "Invalid Pool Size",
    0x85: "Invalid Rotation Period",
    0x86: "Invalid EID Type",
    0x87: "Invalid EID Parameter",
}


def extract_att_error_code(error_message: str) -> Optional[int]:
    """
    Extract ATT error code from a BleakError message.

    BleakError messages often contain ATT error codes in formats like:
    - "ATT error 0x0d"
    - "ATT error code 0x0D"
    - "Error 0x0D"

    Returns:
        The error code as an integer, or None if not found.
    """
    import re

    # Try to match common patterns for ATT error codes
    patterns = [
        r'ATT error code 0x([0-9a-fA-F]{2})',
        r'ATT error 0x([0-9a-fA-F]{2})',
        r'error code 0x([0-9a-fA-F]{2})',
        r'Error 0x([0-9a-fA-F]{2})',
    ]

    for pattern in patterns:
        match = re.search(pattern, error_message, re.IGNORECASE)
        if match:
            return int(match.group(1), 16)

    return None


# Demo errors
class InvalidDeviceError(HubbleError):
    """Invalid device for a given task"""


class ElfFetchError(RuntimeError):
    """Generic failure to fetch or parse an ELF from the Hubble TLDM repo."""


class FlashError(RuntimeError):
    """Generic failure during flashing or target connection."""


__all__ = [
    "HubbleError",
    "BackendError",
    "RequestError",
    "InternalServerError",
    "NetworkError",
    "APITimeout",
    "InvalidCredentialsError",
    "ValidationError",
    "ScanError",
    "DecryptionError",
    "BleError",
    "InvalidDeviceError",
    "ElfFetchError",
    "FlashError",
    "ATT_INVALID_ATTRIBUTE_LENGTH",
    "ATT_INSUFFICIENT_ENCRYPTION",
    "ATT_INVALID_POOL_SIZE",
    "ATT_INVALID_ROTATION_PERIOD",
    "ATT_INVALID_EID_TYPE",
    "ATT_INVALID_EID_PARAMETER",
    "ATT_ERROR_NAMES",
    "extract_att_error_code",
    "raise_for_response",
    "map_http_status",
]


# ----- Helpers for HTTP client code ----------------------------------------


def map_http_status(status_code: int, detail: Optional[str] = None) -> BackendError:
    """
    Map an HTTP status code to a concrete exception instance.
    `detail` should be a short server-provided error message if available.
    """
    msg = f"{status_code}: {detail or 'unexpected response'}"

    if status_code == 400:
        return RequestError(msg)
    if status_code == 500:
        return InternalServerError(msg)
    return BackendError(msg)


def raise_for_response(
    status_code: int,
    body: Any = None,
    *,
    default_message: str = "",
) -> None:
    """
    Raise a specific BackendError subclass based on `status_code` and optional `body`.

    `body` can be a parsed JSON object, a string, or None; we try to extract a helpful
    message from common fields like 'error' or 'message'.
    """
    detail = None
    if isinstance(body, dict):
        detail = (
            body.get("error_description")
            or body.get("error")
            or body.get("message")
            or body.get("detail")
        )
    elif isinstance(body, str):
        detail = body.strip() or None

    if not detail:
        detail = default_message or None

    raise map_http_status(status_code, detail)
