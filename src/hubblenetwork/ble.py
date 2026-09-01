# hubblenetwork/ble.py
from __future__ import annotations

import asyncio
import struct
import time
from collections.abc import AsyncIterator, Iterator
from datetime import datetime, timezone

from bleak import BleakScanner

# Import your dataclass
from .packets import (
    AesEaxPacket,
    EncryptedPacket,
    Location,
    UnencryptedPacket,
    UnknownPacket,
    parse_seq_no,
)

"""
16-bit UUID 0xFCA6 in 128-bit Bluetooth Base UUID form

Bluetooth spec defines a base UUID 0000xxxx-0000-1000-8000-00805F9B34FB.
Any 16-bit (or 32-bit) UUID is expanded into that base by substituting xxxx.

Libraries normalize to consistent 128-bit strings so you don't have to guess
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

HubblePacket = EncryptedPacket | UnencryptedPacket | AesEaxPacket | UnknownPacket


def parse_unencrypted(data: bytes) -> tuple | None:
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
        # AES-CTR advertisement layout: version+seq_no (2) | EID (4) |
        # auth_tag (4) | ciphertext. All three header fields are readable
        # without the key, so they are extracted here rather than at decrypt
        # time and stay available on packets that never decrypt.
        eid = int.from_bytes(raw[2:6], "big") if len(raw) >= 6 else None
        auth_tag = bytes(raw[6:10]) if len(raw) >= 10 else None
        return EncryptedPacket(
            timestamp=ts,
            location=_FAKE_LOCATION,
            payload=raw,
            rssi=rssi,
            protocol_version=version,
            eid=eid,
            auth_tag=auth_tag,
            seq_no=parse_seq_no(raw),
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


def _extract_hubble_service_data(adv_data) -> tuple | None:
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
#
# One scanner, one event loop, for the whole scan.
#
# This used to work the other way round: every caller got a fresh
# BleakScanner wrapped in its own asyncio.run(), and the CLI called that once
# per packet. macOS tolerates it because CoreBluetooth is in-process, but on
# Linux each iteration is a full round trip to bluetoothd over D-Bus (connect,
# register match rules, StartDiscovery, StopDiscovery, drop rules, disconnect)
# and BlueZ serialises discovery state for the whole machine. bleak also keys
# its BlueZManager by event loop and force-finalises the dbus-fast bus of any
# loop that has closed, so the crash arrived after roughly as many packets as
# there had been loop teardowns. Holding the scanner open removes the churn,
# and stops us dropping every advert that landed while no scanner was running.


class _PacketCollector:
    """Turns BleakScanner detection callbacks into a queue of Hubble packets.

    The queue is unbounded on purpose: the consumer only runs between yields,
    so adverts that arrive while it is busy need somewhere to wait.
    """

    def __init__(self) -> None:
        self.queue: asyncio.Queue[HubblePacket] = asyncio.Queue()

    def on_detect(self, device, adv_data) -> None:
        extracted = _extract_hubble_service_data(adv_data)
        if extracted is not None:
            payload, rssi = extracted
            self.queue.put_nowait(_make_packet(payload, rssi))


def _reject_running_loop(sync_name: str, async_name: str) -> None:
    """Fail loudly when a sync scan is called from inside an event loop.

    Checked up front rather than inferred from a RuntimeError escaping the
    scan, because BlueZ and dbus-fast raise RuntimeError too and the old code
    could not tell the two apart: it silently re-ran the whole scan on a new
    loop and never surfaced the real error.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    raise RuntimeError(
        f"{sync_name}() cannot run inside an existing async event loop. "
        f"Use 'await ble.{async_name}()' instead, or install 'nest_asyncio' "
        "for Jupyter support."
    )


def _shutdown_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Drain a loop the way asyncio.run() does, then close it.

    Cancelling leftovers matters here: an abandoned dbus-fast task is what
    produces "Task was destroyed but it is pending" on the way out.
    """
    try:
        pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(
                asyncio.gather(*pending, return_exceptions=True)
            )
        loop.run_until_complete(loop.shutdown_asyncgens())
    finally:
        asyncio.set_event_loop(None)
        loop.close()


async def scan_stream_async(
    timeout: float | None = None,
) -> AsyncIterator[HubblePacket]:
    """Yield Hubble packets as they arrive, holding one scanner open.

    *timeout* is the whole scan window in seconds, not a per-packet wait.
    None scans until the consumer stops asking.

    Usage:
        async for packet in ble.scan_stream_async(timeout=10):
            ...
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    collector = _PacketCollector()

    async with BleakScanner(detection_callback=collector.on_detect):
        while True:
            remaining = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
            try:
                packet = await asyncio.wait_for(
                    collector.queue.get(), timeout=remaining
                )
            except asyncio.TimeoutError:
                return
            yield packet


def scan_stream(timeout: float | None = None) -> Iterator[HubblePacket]:
    """Yield Hubble packets as they arrive, holding one scanner open.

    *timeout* is the whole scan window in seconds, not a per-packet wait.
    None scans until the consumer stops asking, so callers wanting a bounded
    scan should either pass a timeout or break out of the loop.

    For async environments (e.g. Jupyter), use scan_stream_async() instead.

    Usage:
        for packet in ble.scan_stream(timeout=10):
            ...

    Running the loop to completion stops the scanner. If you break out early,
    or an exception leaves the loop, close the generator so discovery stops
    then rather than whenever it is collected:

        with contextlib.closing(ble.scan_stream()) as packets:
            for packet in packets:
                ...
    """
    # Validated here rather than in the generator body so a caller in the wrong
    # context finds out when they call, not on their first next().
    _reject_running_loop("scan_stream", "scan_stream_async")
    return _scan_stream_iter(timeout)


def _scan_stream_iter(timeout: float | None) -> Iterator[HubblePacket]:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stream = scan_stream_async(timeout)
    try:
        while True:
            try:
                yield loop.run_until_complete(stream.__anext__())
            except StopAsyncIteration:
                return
    finally:
        # Closing the async generator is what runs BleakScanner's __aexit__,
        # so the single StopDiscovery happens here even if the consumer broke
        # out of the loop early.
        try:
            loop.run_until_complete(stream.aclose())
        finally:
            _shutdown_loop(loop)


def scan(timeout: float) -> list[HubblePacket]:
    """
    Scan for BLE advertisements that include service data for UUID 0xFCA6.
    Automatically detects encrypted vs unencrypted protocol packets.

    Buffers the whole window; use scan_stream() to handle packets as they land.
    For async environments (e.g., Jupyter), use scan_async() instead.
    """
    return list(scan_stream(timeout))


async def scan_async(timeout: float) -> list[HubblePacket]:
    """
    Async version of scan() for use in async environments like Jupyter notebooks.

    Usage:
        packets = await ble.scan_async(timeout=5.0)
    """
    return [packet async for packet in scan_stream_async(timeout)]


def scan_single(timeout: float | None = None) -> HubblePacket | None:
    """
    Scan for a BLE advertisement that includes service data for UUID 0xFCA6
    and return the first one. Automatically detects encrypted vs unencrypted
    protocol.

    Starts and stops a scanner per call, so use scan_stream() to read more than
    one packet rather than calling this in a loop.

    For async environments (e.g., Jupyter), use scan_single_async() instead.
    """
    stream = scan_stream(timeout)
    try:
        return next(stream, None)
    finally:
        stream.close()


async def scan_single_async(timeout: float | None = None) -> HubblePacket | None:
    """
    Async version of scan_single() for use in async environments like Jupyter
    notebooks.

    Usage:
        packet = await ble.scan_single_async(timeout=5.0)
    """
    stream = scan_stream_async(timeout)
    try:
        async for packet in stream:
            return packet
        return None
    finally:
        await stream.aclose()
