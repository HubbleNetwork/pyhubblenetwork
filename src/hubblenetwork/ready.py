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
from typing import Callable, List, Optional, Dict, Any

from bleak import BleakScanner, BleakClient

# 16-bit UUID 0xFCA7 in 128-bit Bluetooth Base UUID form
HUBBLE_READY_SERVICE_UUID = "0000fca7-0000-1000-8000-00805f9b34fb"

# Hubble Provisioning Service Characteristic UUIDs
CHAR_STATUS_UUID = "00000001-fca7-4000-8000-00805f9b34fb"
CHAR_CHALLENGE_RESPONSE_UUID = "00000002-fca7-4000-8000-00805f9b34fb"
CHAR_DEVICE_KEY_UUID = "00000003-fca7-4000-8000-00805f9b34fb"
CHAR_DEVICE_CONFIG_UUID = "00000004-fca7-4000-8000-00805f9b34fb"
CHAR_EPOCH_TIME_UUID = "00000005-fca7-4000-8000-00805f9b34fb"

# Characteristic name mapping for display
CHAR_NAMES = {
    CHAR_STATUS_UUID: "Status",
    CHAR_CHALLENGE_RESPONSE_UUID: "Challenge/Response",
    CHAR_DEVICE_KEY_UUID: "Device Key",
    CHAR_DEVICE_CONFIG_UUID: "Device Configuration",
    CHAR_EPOCH_TIME_UUID: "Epoch Time",
}


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


@dataclass(frozen=True)
class StatusCharacteristic:
    """Parsed Status characteristic (0x0001) data."""

    version_major: int
    version_minor: int
    version_patch: int
    is_locked: bool
    key_written: bool
    config_written: bool
    epoch_time_written: bool

    @classmethod
    def from_bytes(cls, data: bytes) -> "StatusCharacteristic":
        """Parse Status characteristic from raw bytes."""
        if len(data) < 4:
            raise ValueError(f"Status data too short: {len(data)} bytes, need at least 4")

        version_major = data[0]
        version_minor = data[1]
        # bytes 2-3 are uint16 LE for patch version
        version_patch = int.from_bytes(data[2:4], byteorder="little")

        # Flags byte is at position 4 (if present)
        flags = data[4] if len(data) > 4 else 0
        is_locked = bool(flags & 0x01)
        key_written = bool(flags & 0x02)
        config_written = bool(flags & 0x04)
        epoch_time_written = bool(flags & 0x08)

        return cls(
            version_major=version_major,
            version_minor=version_minor,
            version_patch=version_patch,
            is_locked=is_locked,
            key_written=key_written,
            config_written=config_written,
            epoch_time_written=epoch_time_written,
        )

    @property
    def version_string(self) -> str:
        return f"{self.version_major}.{self.version_minor}.{self.version_patch}"

    @property
    def mode_string(self) -> str:
        return "Locked Mode" if self.is_locked else "Open Mode"

    def to_display_string(self) -> str:
        parts = [f"v{self.version_string}", self.mode_string]
        flags = []
        flags.append(f"Key={'Yes' if self.key_written else 'No'}")
        flags.append(f"Config={'Yes' if self.config_written else 'No'}")
        flags.append(f"Time={'Yes' if self.epoch_time_written else 'No'}")
        return f"{parts[0]}, {parts[1]}\n{', '.join(flags)}"


@dataclass(frozen=True)
class DeviceKeyInfo:
    """Parsed Device Key characteristic (0x0003) read data."""

    supports_aes_256_ctr: bool
    supports_aes_128_ctr: bool

    @classmethod
    def from_bytes(cls, data: bytes) -> "DeviceKeyInfo":
        """Parse Device Key info from raw bytes."""
        if len(data) < 1:
            raise ValueError("Device Key data too short")

        flags = data[0]
        return cls(
            supports_aes_256_ctr=bool(flags & 0x01),
            supports_aes_128_ctr=bool(flags & 0x02),
        )

    def to_display_string(self) -> str:
        modes = []
        if self.supports_aes_256_ctr:
            modes.append("AES-256-CTR")
        if self.supports_aes_128_ctr:
            modes.append("AES-128-CTR")
        return ", ".join(modes) if modes else "None"


@dataclass(frozen=True)
class CharacteristicInfo:
    """Information about a read characteristic."""

    uuid: str
    name: str
    raw_value: bytes
    parsed_value: Optional[str]


def _parse_device_config(data: bytes) -> str:
    """Parse Device Configuration characteristic."""
    if len(data) < 1:
        return "Not configured"

    eid_type = data[0]
    eid_type_str = "UTC-based" if eid_type == 0x00 else "Counter-based" if eid_type == 0x01 else f"Unknown ({eid_type})"

    if len(data) >= 5:
        rotation_period = int.from_bytes(data[1:5], byteorder="little")
        rotation_str = f", Rotation: {rotation_period}" if rotation_period > 0 else ""
    else:
        rotation_str = ""

    return f"EID: {eid_type_str}{rotation_str}"


def _parse_epoch_time(data: bytes) -> str:
    """Parse Epoch Time characteristic."""
    if len(data) < 8:
        return "Not set"

    timestamp = int.from_bytes(data[0:8], byteorder="little")
    if timestamp == 0:
        return "Not set"

    from datetime import datetime, timezone
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, OSError):
        return f"Invalid ({timestamp})"


async def _connect_and_read_characteristics_async(
    address: str, timeout: float = 30.0
) -> List[CharacteristicInfo]:
    """Connect to device and read all Hubble Provisioning Service characteristics."""
    results: List[CharacteristicInfo] = []

    async with BleakClient(address, timeout=timeout) as client:
        # Read each characteristic in order
        char_uuids = [
            CHAR_STATUS_UUID,
            CHAR_DEVICE_KEY_UUID,
            CHAR_DEVICE_CONFIG_UUID,
            CHAR_EPOCH_TIME_UUID,
        ]

        for uuid in char_uuids:
            name = CHAR_NAMES.get(uuid, "Unknown")
            try:
                data = await client.read_gatt_char(uuid)
                data = bytes(data)

                # Parse based on characteristic type
                parsed: Optional[str] = None
                if uuid == CHAR_STATUS_UUID:
                    try:
                        status = StatusCharacteristic.from_bytes(data)
                        parsed = status.to_display_string()
                    except Exception:
                        parsed = f"Parse error: {data.hex()}"
                elif uuid == CHAR_DEVICE_KEY_UUID:
                    try:
                        key_info = DeviceKeyInfo.from_bytes(data)
                        parsed = key_info.to_display_string()
                    except Exception:
                        parsed = f"Parse error: {data.hex()}"
                elif uuid == CHAR_DEVICE_CONFIG_UUID:
                    try:
                        parsed = _parse_device_config(data)
                    except Exception:
                        parsed = f"Parse error: {data.hex()}"
                elif uuid == CHAR_EPOCH_TIME_UUID:
                    try:
                        parsed = _parse_epoch_time(data)
                    except Exception:
                        parsed = f"Parse error: {data.hex()}"
                else:
                    parsed = data.hex()

                results.append(
                    CharacteristicInfo(uuid=uuid, name=name, raw_value=data, parsed_value=parsed)
                )
            except Exception as e:
                results.append(
                    CharacteristicInfo(uuid=uuid, name=name, raw_value=b"", parsed_value=f"Read error: {e}")
                )

    return results


def connect_and_read_characteristics(
    address: str, timeout: float = 30.0
) -> List[CharacteristicInfo]:
    """
    Connect to a Hubble Ready device and read all provisioning characteristics.

    Args:
        address: BLE address of the device
        timeout: Connection timeout in seconds

    Returns:
        List of CharacteristicInfo objects with parsed values
    """
    try:
        return asyncio.run(_connect_and_read_characteristics_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    _connect_and_read_characteristics_async(address, timeout)
                )
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
