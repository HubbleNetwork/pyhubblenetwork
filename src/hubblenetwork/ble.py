# hubblenetwork/ble.py
from __future__ import annotations
import asyncio
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional, List

from bleak import BleakScanner

from .packets import (
    Location,
    EncryptedPacket,
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

# BLE scan parameters (units of 0.625 ms, per Bluetooth Core Spec)
# 160 ticks = 100 ms.  100% duty cycle (interval == window) gives the highest
# probability of catching a 2-second advertising interval within a short scan.
_DEFAULT_SCAN_INTERVAL = 160  # 100 ms
_DEFAULT_SCAN_WINDOW = 160  # 100 ms


def _configure_linux_scan_params(
    interval_ticks: int = _DEFAULT_SCAN_INTERVAL,
    window_ticks: int = _DEFAULT_SCAN_WINDOW,
) -> None:
    """Attempt to set BLE scan parameters via btmgmt (Linux only).

    Silently no-ops on non-Linux platforms or when the process lacks
    CAP_NET_ADMIN (i.e. not running as root).  Values are in units of
    0.625 ms as defined by the Bluetooth Core Specification.
    """
    if sys.platform != "linux":
        return
    try:
        subprocess.run(
            ["btmgmt", "le-scan-params", str(interval_ticks), str(window_ticks)],
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def _get_location() -> Optional[Location]:
    # Return an unreasonable location
    return Location(lat=90, lon=0, fake=True)


async def _scan_async(
    ttl: float,
    scan_interval: int = _DEFAULT_SCAN_INTERVAL,
    scan_window: int = _DEFAULT_SCAN_WINDOW,
) -> List[EncryptedPacket]:
    """Async implementation of BLE scan."""
    _configure_linux_scan_params(scan_interval, scan_window)
    done = asyncio.Event()
    packets: List[EncryptedPacket] = []

    def on_detect(device, adv_data) -> None:
        nonlocal packets
        # Normalize to a dict; bleak provides service_data as {uuid_str: bytes}
        service_data = getattr(adv_data, "service_data", None) or {}
        service_uuids = getattr(adv_data, "service_uuids", None) or []
        payload = None

        # Fast path: skip if target UUID not in advertised service UUIDs
        if _TARGET_UUID not in service_uuids:
            return

        # Keys are 128-bit UUID strings; compare lowercased
        for uuid_str, data in service_data.items():
            if (uuid_str or "").lower() == _TARGET_UUID:
                payload = bytes(data)
                break

        if payload is not None:
            rssi = getattr(adv_data, "rssi", getattr(device, "rssi", 0)) or 0
            packets.append(
                EncryptedPacket(
                    timestamp=int(datetime.now(timezone.utc).timestamp()),
                    location=_get_location(),
                    payload=payload,
                    rssi=int(rssi),
                )
            )

    # Start scanning and wait for first match or timeout.
    # Pass service_uuids to enable OS-level filtering, reducing Python callback volume.
    # Use passive scanning: Hubble beacons are non-connectable undirected advertisements
    # that never respond to scan requests, so active mode wastes airtime.
    async with BleakScanner(
        detection_callback=on_detect,
        service_uuids=[_TARGET_UUID],
        scanning_mode="passive",
    ):
        try:
            await asyncio.wait_for(done.wait(), timeout=ttl)
        except asyncio.TimeoutError:
            pass

    return packets


def scan(
    timeout: float,
    scan_interval: int = _DEFAULT_SCAN_INTERVAL,
    scan_window: int = _DEFAULT_SCAN_WINDOW,
) -> List[EncryptedPacket]:
    """
    Scan for BLE advertisements that include service data for UUID 0xFCA6 and
    return them as a List[EncryptedPacket] (payload=data bytes, rssi from the adv).

    scan_interval and scan_window are in units of 0.625 ms (Linux only, requires
    root/CAP_NET_ADMIN).  The defaults give 100% duty cycle (100 ms / 100 ms),
    which is recommended for devices that advertise every ~2 seconds.

    For async environments (e.g., Jupyter), use scan_async() instead.
    """
    try:
        return asyncio.run(_scan_async(timeout, scan_interval, scan_window))
    except RuntimeError:
        # Fallback for environments with an active loop (e.g., Jupyter notebooks).
        # Note: For Jupyter, consider installing nest_asyncio for better compatibility.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop, create a new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    _scan_async(timeout, scan_interval, scan_window)
                )
            finally:
                loop.close()
        # If there's a running loop, we can't use run_until_complete
        raise RuntimeError(
            "Cannot run synchronous BLE scan inside an existing async event loop. "
            "Use 'await ble.scan_async()' or install 'nest_asyncio' for Jupyter support."
        )


async def scan_async(
    timeout: float,
    scan_interval: int = _DEFAULT_SCAN_INTERVAL,
    scan_window: int = _DEFAULT_SCAN_WINDOW,
) -> List[EncryptedPacket]:
    """
    Async version of scan() for use in async environments like Jupyter notebooks.

    Usage:
        packets = await ble.scan_async(timeout=5.0)
    """
    return await _scan_async(timeout, scan_interval, scan_window)


async def _scan_single_async(
    ttl: float,
    scan_interval: int = _DEFAULT_SCAN_INTERVAL,
    scan_window: int = _DEFAULT_SCAN_WINDOW,
) -> Optional[EncryptedPacket]:
    """Async implementation for scanning a single BLE packet."""
    _configure_linux_scan_params(scan_interval, scan_window)
    done = asyncio.Event()
    packet: Optional[EncryptedPacket] = None

    def on_detect(device, adv_data) -> None:
        nonlocal packet

        # If we already found a packet, ignore further callbacks
        if packet is not None:
            return

        # Normalize to a dict; bleak provides service_data as {uuid_str: bytes}
        service_data = getattr(adv_data, "service_data", None) or {}
        service_uuids = getattr(adv_data, "service_uuids", None) or []
        payload = None

        if _TARGET_UUID not in service_uuids:
            return

        # Keys are 128-bit UUID strings; compare lowercased
        for uuid_str, data in service_data.items():
            if (uuid_str or "").lower() == _TARGET_UUID:
                payload = bytes(data)
                break

        if payload is None:
            return

        rssi = getattr(adv_data, "rssi", getattr(device, "rssi", 0)) or 0
        packet = EncryptedPacket(
            timestamp=int(datetime.now(timezone.utc).timestamp()),
            location=_get_location(),
            payload=payload,
            rssi=int(rssi),
        )
        done.set()

    # Start scanning and wait for first match or timeout.
    # Pass service_uuids to enable OS-level filtering, reducing Python callback volume.
    # Use passive scanning: Hubble beacons are non-connectable undirected advertisements
    # that never respond to scan requests, so active mode wastes airtime.
    async with BleakScanner(
        detection_callback=on_detect,
        service_uuids=[_TARGET_UUID],
        scanning_mode="passive",
    ):
        try:
            await asyncio.wait_for(done.wait(), timeout=ttl)
        except asyncio.TimeoutError:
            pass

    return packet


def scan_single(
    timeout: float,
    scan_interval: int = _DEFAULT_SCAN_INTERVAL,
    scan_window: int = _DEFAULT_SCAN_WINDOW,
) -> Optional[EncryptedPacket]:
    """
    Scan for a BLE advertisement that includes service data for UUID 0xFCA6 and
    return it.

    scan_interval and scan_window are in units of 0.625 ms (Linux only, requires
    root/CAP_NET_ADMIN).  The defaults give 100% duty cycle (100 ms / 100 ms),
    which is recommended for devices that advertise every ~2 seconds.

    For async environments (e.g., Jupyter), use scan_single_async() instead.
    """
    try:
        return asyncio.run(_scan_single_async(timeout, scan_interval, scan_window))
    except RuntimeError:
        # Fallback for environments with an active loop (e.g., Jupyter notebooks).
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop, create a new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    _scan_single_async(timeout, scan_interval, scan_window)
                )
            finally:
                loop.close()
        # If there's a running loop, we can't use run_until_complete
        raise RuntimeError(
            "Cannot run synchronous BLE scan inside an existing async event loop. "
            "Use 'await ble.scan_single_async()' or install 'nest_asyncio' for Jupyter support."
        )


async def scan_single_async(
    timeout: float,
    scan_interval: int = _DEFAULT_SCAN_INTERVAL,
    scan_window: int = _DEFAULT_SCAN_WINDOW,
) -> Optional[EncryptedPacket]:
    """
    Async version of scan_single() for use in async environments like Jupyter notebooks.

    Usage:
        packet = await ble.scan_single_async(timeout=5.0)
    """
    return await _scan_single_async(timeout, scan_interval, scan_window)
