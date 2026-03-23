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
