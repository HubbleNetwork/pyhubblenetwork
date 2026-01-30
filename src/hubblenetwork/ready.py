# hubblenetwork/ready.py
"""
Hubble Ready device provisioning module.

This module handles provisioning of devices advertising the Hubble Provisioning
Service (0xFCA7). Unlike beacon scanning (0xFCA6) which is passive, provisioning
involves active GATT connections and characteristic writes.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, List, Optional

from bleak import BleakScanner

# 16-bit UUID 0xFCA7 in 128-bit Bluetooth Base UUID form
HUBBLE_READY_SERVICE_UUID = "0000fca7-0000-1000-8000-00805f9b34fb"


@dataclass(frozen=True)
class HubbleReadyDevice:
    """A device advertising the Hubble Provisioning Service (0xFCA7)."""

    name: Optional[str]
    address: str
    rssi: int


async def _scan_ready_devices_async(timeout: float) -> List[HubbleReadyDevice]:
    """Async implementation of Hubble Ready device scan."""
    devices: List[HubbleReadyDevice] = []
    seen_addresses: set[str] = set()

    def on_detect(device, adv_data) -> None:
        nonlocal devices, seen_addresses

        # Skip if we've already seen this device
        if device.address in seen_addresses:
            return

        # Check if device is advertising the Hubble Ready service
        service_uuids = getattr(adv_data, "service_uuids", None) or []
        service_uuids_lower = [u.lower() for u in service_uuids]

        if HUBBLE_READY_SERVICE_UUID not in service_uuids_lower:
            return

        seen_addresses.add(device.address)
        rssi = getattr(adv_data, "rssi", getattr(device, "rssi", 0)) or 0
        name = adv_data.local_name or device.name

        devices.append(
            HubbleReadyDevice(
                name=name,
                address=device.address,
                rssi=int(rssi),
            )
        )

    async with BleakScanner(detection_callback=on_detect):
        await asyncio.sleep(timeout)

    # Sort by RSSI (strongest signal first)
    devices.sort(key=lambda d: d.rssi, reverse=True)
    return devices


def scan_ready_devices(timeout: float = 10.0) -> List[HubbleReadyDevice]:
    """
    Scan for BLE devices advertising the Hubble Provisioning Service (0xFCA7).

    Args:
        timeout: How long to scan in seconds (default: 10.0)

    Returns:
        List of HubbleReadyDevice objects sorted by RSSI (strongest first)
    """
    try:
        return asyncio.run(_scan_ready_devices_async(timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_scan_ready_devices_async(timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE scan inside an existing async event loop. "
            "Use 'await ready.scan_ready_devices_async()' instead."
        )


async def scan_ready_devices_async(timeout: float = 10.0) -> List[HubbleReadyDevice]:
    """
    Async version of scan_ready_devices() for use in async environments.

    Usage:
        devices = await ready.scan_ready_devices_async(timeout=10.0)
    """
    return await _scan_ready_devices_async(timeout)


async def _scan_ready_devices_streaming_async(
    timeout: float,
    on_device: Callable[[HubbleReadyDevice], None],
) -> List[HubbleReadyDevice]:
    """Async scan that calls on_device callback for each discovered device."""
    devices: List[HubbleReadyDevice] = []
    seen_addresses: set[str] = set()

    def on_detect(device, adv_data) -> None:
        nonlocal devices, seen_addresses

        if device.address in seen_addresses:
            return

        service_uuids = getattr(adv_data, "service_uuids", None) or []
        service_uuids_lower = [u.lower() for u in service_uuids]

        if HUBBLE_READY_SERVICE_UUID not in service_uuids_lower:
            return

        seen_addresses.add(device.address)
        rssi = getattr(adv_data, "rssi", getattr(device, "rssi", 0)) or 0
        name = adv_data.local_name or device.name

        dev = HubbleReadyDevice(
            name=name,
            address=device.address,
            rssi=int(rssi),
        )
        devices.append(dev)
        on_device(dev)

    async with BleakScanner(detection_callback=on_detect):
        await asyncio.sleep(timeout)

    return devices


def scan_ready_devices_streaming(
    timeout: float,
    on_device: Callable[[HubbleReadyDevice], None],
) -> List[HubbleReadyDevice]:
    """
    Scan for Hubble Ready devices with streaming output.

    Calls on_device callback immediately when each device is discovered.

    Args:
        timeout: How long to scan in seconds
        on_device: Callback called with each HubbleReadyDevice as discovered

    Returns:
        List of all discovered devices
    """
    try:
        return asyncio.run(_scan_ready_devices_streaming_async(timeout, on_device))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    _scan_ready_devices_streaming_async(timeout, on_device)
                )
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE scan inside an existing async event loop."
        )
