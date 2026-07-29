# hubble/packets.py
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Location:
    """Geographic location (WGS84)."""

    lat: float
    lon: float
    alt_m: float | None = None  # altitude meters, if known
    fake: bool = False


# AES-CTR advertisement layout: version(6 bits) + seq_no(10 bits) | EID(4) |
# auth_tag(4) | ciphertext. The sequence number shares the first two bytes with
# the protocol version, so it needs masking off.
SEQ_NO_MASK = 0x3FF


def parse_seq_no(ble_adv: bytes) -> int | None:
    """Read the 10-bit sequence number from an AES-CTR advertisement.

    Available without the encryption key, which is why it can be displayed for
    packets that have not been decrypted.
    """
    if len(ble_adv) < 2:
        return None
    return int.from_bytes(ble_adv[0:2], "big") & SEQ_NO_MASK


@dataclass(frozen=True)
class EncryptedPacket:
    """A packet received locally (e.g., via BLE) that has not been decrypted."""

    timestamp: int  # timezone-aware UTC recommended
    location: Location | None  # None if unknown
    payload: bytes  # opaque encrypted bytes
    rssi: int  # received signal strength (dBm)
    # Fields extracted from the raw advertisement, when present. AES-CTR
    # carries auth_tag but no EID; None means the field isn't applicable.
    protocol_version: int | None = None
    eid: int | None = None
    auth_tag: bytes | None = None
    # 10-bit sequence number from the advertisement header. Readable without the
    # key, so it stays useful on packets that could not be decrypted.
    seq_no: int | None = None


@dataclass(frozen=True)
class UnencryptedPacket:
    """A packet received via BLE using the unencrypted Hubble protocol."""

    timestamp: int
    location: Location | None
    network_id: int  # 34-bit static network ID
    protocol_version: int  # 6-bit protocol version
    payload: bytes  # 0-18 bytes customer payload
    rssi: int


@dataclass(frozen=True)
class AesEaxPacket:
    """A packet using AES-EAX authenticated encryption (protocol version 2)."""

    timestamp: int
    location: Location | None
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
    location: Location | None
    protocol_version: int
    payload: bytes
    rssi: int


@dataclass(frozen=True)
class DecryptedPacket:
    """A packet decrypted by backend or locally."""

    timestamp: int
    device_id: str
    device_name: str
    location: Location | None
    tags: dict[str, str]  # arbitrary tags
    payload: bytes  # decrypted payload bytes
    rssi: int  # received signal strength (dBm)
    counter: int | None = None
    sequence: int | None = None
    # Preserved from the raw packet so the original version / EID / auth tag
    # can still be displayed alongside the decrypted payload. AES-CTR has no
    # EID.
    protocol_version: int | None = None
    eid: int | None = None
    auth_tag: bytes | None = None


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
    # 4-byte CMAC auth tag, when reported by the receiver. Needed to locally
    # decrypt the payload (identifies the day counter); None if unavailable.
    auth_tag: bytes | None = None
    pdu_n_corr: int | None = None   # Reed-Solomon corrections on PDU (None for OOK/v-1)
    header_n_corr: int | None = None  # Reed-Solomon corrections on header
    sym_mean_ms: float | None = None  # average symbol duration from envelope analysis
    gap_mean_ms: float | None = None  # average inter-symbol gap duration
