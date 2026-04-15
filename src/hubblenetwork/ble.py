# hubblenetwork/ble.py
from __future__ import annotations
import asyncio
import struct
from datetime import datetime, timezone
from typing import Optional, List, Union

from bleak import BleakScanner

# Import your dataclass
from .packets import (
    Location,
    EncryptedPacket,
    UnencryptedPacket,
    AesEaxPacket,
    UnknownPacket,
)

"""
16-bit UUID 0xFCA6 in 128-bit Bluetooth Base UUID form

Bluetooth spec defines a base UUID 0000xxxx-0000-1000-8000-00805F9B34FB.
Any 16-bit (or 32-bit) UUID is expanded into that base by substituting xxxx.

Libraries normalize to consistent 128-bit strings so you don’t have to guess
whether a platform will report 16- vs 128-bit in scan results.

In bleak, AdvertisementData.service_uuids and the keys in AdvertisementData.service_data
are 128-bit strings. So matching against the normalized 128-bit form is the most portable.
"""
_TARGET_UUID = "0000fca6-0000-1000-8000-00805f9b34fb"


_FAKE_LOCATION = Location(lat=90, lon=0, fake=True)

# ---------------------------------------------------------------------------
# Unencrypted protocol parsing (version 1)
# ---------------------------------------------------------------------------

_NETWORK_ID_MASK = (1 << 34) - 1

HubblePacket = Union[EncryptedPacket, UnencryptedPacket, AesEaxPacket, UnknownPacket]


def parse_unencrypted(data: bytes) -> Optional[tuple]:
    """Parse unencrypted protocol service data bytes.

    Returns (protocol_version, network_id, payload) or None if *data* does
    not look like an unencrypted-protocol advertisement (e.g. version == 0
    means it is an encrypted packet).
    """
    if len(data) < 5:
        return None
    header = int.from_bytes(data[0:5], "big")
    version = header >> 34
    if version == 0:
        return None
    network_id = header & _NETWORK_ID_MASK
    return (version, network_id, data[5:])


_AES_EAX_MIN_SIZE = 15  # version(1) + salt(2) + EID(8) + tag(4)
_AES_EAX_TAG_SIZE = 4


def _make_packet(raw: bytes, rssi: int) -> HubblePacket:
    """Build the right packet type from raw service data bytes."""
    ts = int(datetime.now(timezone.utc).timestamp())

    if len(raw) < 1:
        return EncryptedPacket(
            timestamp=ts, location=_FAKE_LOCATION, payload=raw, rssi=rssi
        )

    version = raw[0] >> 2

    if version == 0:
        return EncryptedPacket(
            timestamp=ts, location=_FAKE_LOCATION, payload=raw, rssi=rssi
        )
    elif version == 1:
        parsed = parse_unencrypted(raw)
        if parsed is not None:
            ver, network_id, customer_payload = parsed
            return UnencryptedPacket(
                timestamp=ts,
                location=_FAKE_LOCATION,
                network_id=network_id,
                protocol_version=ver,
                payload=customer_payload,
                rssi=rssi,
            )
    elif version == 2 and len(raw) >= _AES_EAX_MIN_SIZE:
        nonce_salt = raw[1:3]
        eid = struct.unpack("<Q", raw[3:11])[0]
        auth_tag = raw[-_AES_EAX_TAG_SIZE:]
        payload = raw[11:-_AES_EAX_TAG_SIZE] if len(raw) > _AES_EAX_MIN_SIZE else b""
        return AesEaxPacket(
            timestamp=ts,
            location=_FAKE_LOCATION,
            protocol_version=version,
            nonce_salt=nonce_salt,
            eid=eid,
            payload=payload,
            auth_tag=auth_tag,
            rssi=rssi,
        )

    return UnknownPacket(
        timestamp=ts,
        location=_FAKE_LOCATION,
        protocol_version=version,
        payload=raw,
        rssi=rssi,
    )


def _extract_hubble_service_data(adv_data) -> Optional[tuple]:
    """Extract Hubble service data payload and RSSI from a BLE advertisement.

    Returns (payload_bytes, rssi) or None if UUID 0xFCA6 not present.
    """
    service_data = getattr(adv_data, "service_data", None) or {}
    for uuid_str, data in service_data.items():
        if (uuid_str or "").lower() == _TARGET_UUID:
            return (bytes(data), int(getattr(adv_data, "rssi", 0) or 0))
    return None


# ---------------------------------------------------------------------------
# Scanning (auto-detects encrypted vs unencrypted)
# ---------------------------------------------------------------------------


async def _scan_async(ttl: float) -> List[HubblePacket]:
    """Async implementation of BLE scan."""
    done = asyncio.Event()
    packets: List[HubblePacket] = []

    def on_detect(device, adv_data) -> None:
        nonlocal packets
        extracted = _extract_hubble_service_data(adv_data)
        if extracted is not None:
            payload, rssi = extracted
            packets.append(_make_packet(payload, rssi))

    async with BleakScanner(detection_callback=on_detect):
        try:
            await asyncio.wait_for(done.wait(), timeout=ttl)
        except asyncio.TimeoutError:
            pass

    return packets


def scan(timeout: float) -> List[HubblePacket]:
    """
    Scan for BLE advertisements that include service data for UUID 0xFCA6.
    Automatically detects encrypted vs unencrypted protocol packets.

    For async environments (e.g., Jupyter), use scan_async() instead.
    """
    try:
        return asyncio.run(_scan_async(timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_scan_async(timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE scan inside an existing async event loop. "
            "Use 'await ble.scan_async()' or install 'nest_asyncio' for Jupyter support."
        )


async def scan_async(timeout: float) -> List[HubblePacket]:
    """
    Async version of scan() for use in async environments like Jupyter notebooks.

    Usage:
        packets = await ble.scan_async(timeout=5.0)
    """
    return await _scan_async(timeout)


async def _scan_single_async(ttl: float) -> Optional[HubblePacket]:
    """Async implementation for scanning a single BLE packet."""
    done = asyncio.Event()
    packet: Optional[HubblePacket] = None

    def on_detect(device, adv_data) -> None:
        nonlocal packet

        if packet is not None:
            return

        extracted = _extract_hubble_service_data(adv_data)
        if extracted is None:
            return

        payload, rssi = extracted
        packet = _make_packet(payload, rssi)
        done.set()

    async with BleakScanner(detection_callback=on_detect):
        try:
            await asyncio.wait_for(done.wait(), timeout=ttl)
        except asyncio.TimeoutError:
            pass

    return packet


def scan_single(timeout: float) -> Optional[HubblePacket]:
    """
    Scan for a BLE advertisement that includes service data for UUID 0xFCA6
    and return it. Automatically detects encrypted vs unencrypted protocol.

    For async environments (e.g., Jupyter), use scan_single_async() instead.
    """
    try:
        return asyncio.run(_scan_single_async(timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_scan_single_async(timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE scan inside an existing async event loop. "
            "Use 'await ble.scan_single_async()' or install 'nest_asyncio' for Jupyter support."
        )


async def scan_single_async(timeout: float) -> Optional[HubblePacket]:
    """
    Async version of scan_single() for use in async environments like Jupyter notebooks.

    Usage:
        packet = await ble.scan_single_async(timeout=5.0)
    """
    return await _scan_single_async(timeout)
