# hubble/packets.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict


@dataclass(frozen=True)
class Location:
    """Geographic location (WGS84)."""

    lat: float
    lon: float
    alt_m: Optional[float] = None  # altitude meters, if known
    fake: bool = False


@dataclass(frozen=True)
class EncryptedPacket:
    """A packet received locally (e.g., via BLE) that has not been decrypted."""

    timestamp: int  # timezone-aware UTC recommended
    location: Optional[Location]  # None if unknown
    payload: bytes  # opaque encrypted bytes
    rssi: int  # received signal strength (dBm)
    # Fields extracted from the raw advertisement, when present. AES-CTR
    # carries auth_tag but no EID; None means the field isn't applicable.
    protocol_version: Optional[int] = None
    eid: Optional[int] = None
    auth_tag: Optional[bytes] = None


@dataclass(frozen=True)
class UnencryptedPacket:
    """A packet received via BLE using the unencrypted Hubble protocol."""

    timestamp: int
    location: Optional[Location]
    network_id: int  # 34-bit static network ID
    protocol_version: int  # 6-bit protocol version
    payload: bytes  # 0-18 bytes customer payload
    rssi: int


@dataclass(frozen=True)
class AesEaxPacket:
    """A packet using AES-EAX authenticated encryption (protocol version 2)."""

    timestamp: int
    location: Optional[Location]
    protocol_version: int  # 6-bit version (2 for AES-EAX)
    nonce_salt: bytes  # 2 bytes, random per-message
    eid: int  # 8-byte EID as uint64
    payload: bytes  # 0-9 bytes encrypted
    auth_tag: bytes  # 4 bytes AEAD tag
    rssi: int


@dataclass(frozen=True)
class UnknownPacket:
    """A packet with an unrecognized protocol version."""

    timestamp: int
    location: Optional[Location]
    protocol_version: int
    payload: bytes
    rssi: int


@dataclass(frozen=True)
class DecryptedPacket:
    """A packet decrypted by backend or locally."""

    timestamp: int
    device_id: str
    device_name: str
    location: Optional[Location]
    tags: Dict[str, str]  # arbitrary tags
    payload: bytes  # decrypted payload bytes
    rssi: int  # received signal strength (dBm)
    counter: Optional[int] = None
    sequence: Optional[int] = None
    # Preserved from the raw packet so the original version / EID / auth tag
    # can still be displayed alongside the decrypted payload. AES-CTR has no
    # EID.
    protocol_version: Optional[int] = None
    eid: Optional[int] = None
    auth_tag: Optional[bytes] = None


@dataclass(frozen=True)
class SatellitePacket:
    """A packet decoded by the satellite receiver (PlutoSDR)."""

    device_id: str  # e.g. "0xBB2973BD"
    seq_num: int
    device_type: str  # e.g. "silabs"
    timestamp: float  # Unix timestamp
    rssi_dB: float  # signal strength in dB
    channel_num: int
    freq_offset_hz: float
    payload: bytes  # encrypted payload bytes (base64-decoded from API)
