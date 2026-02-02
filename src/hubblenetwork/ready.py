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
from typing import TYPE_CHECKING, Callable, List, Optional

from bleak import BleakScanner, BleakClient

# Type hint import for Organization (avoid circular import at runtime)
if TYPE_CHECKING:
    from .org import Organization

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


async def _read_status_async(address: str, timeout: float = 30.0) -> StatusCharacteristic:
    """Async implementation of read_status."""
    async with BleakClient(address, timeout=timeout) as client:
        data = await client.read_gatt_char(CHAR_STATUS_UUID)
        return StatusCharacteristic.from_bytes(bytes(data))


def read_status(address: str, timeout: float = 30.0) -> StatusCharacteristic:
    """
    Read the Status characteristic from a Hubble Ready device.

    Args:
        address: BLE address of the device
        timeout: Connection timeout in seconds (default: 30.0)

    Returns:
        StatusCharacteristic with version and provisioning flags

    Raises:
        BleakError: If connection fails or read operation fails
    """
    try:
        return asyncio.run(_read_status_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_read_status_async(address, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )


@dataclass(frozen=True)
class DeviceKeyInfo:
    """Parsed Device Key characteristic (0x0003) read data."""

    encryption_mode: str  # "AES-256-CTR" or "AES-128-CTR"
    encryption_mode_code: int  # 0x01 for AES-256-CTR, 0x02 for AES-128-CTR

    @classmethod
    def from_bytes(cls, data: bytes) -> "DeviceKeyInfo":
        """Parse Device Key info from raw bytes."""
        if len(data) < 1:
            raise ValueError("Device Key data too short")

        mode_byte = data[0]
        if mode_byte == 0x01:
            encryption_mode = "AES-256-CTR"
        elif mode_byte == 0x02:
            encryption_mode = "AES-128-CTR"
        else:
            raise ValueError(f"Unknown encryption mode: 0x{mode_byte:02x}")

        return cls(encryption_mode=encryption_mode, encryption_mode_code=mode_byte)

    @property
    def key_size(self) -> int:
        """Return the key size in bytes for this encryption mode."""
        return 32 if self.encryption_mode == "AES-256-CTR" else 16

    def to_display_string(self) -> str:
        return self.encryption_mode


async def _read_key_info_async(address: str, timeout: float = 30.0) -> DeviceKeyInfo:
    """Async implementation of read_key_info."""
    async with BleakClient(address, timeout=timeout) as client:
        data = await client.read_gatt_char(CHAR_DEVICE_KEY_UUID)
        return DeviceKeyInfo.from_bytes(bytes(data))


def read_key_info(address: str, timeout: float = 30.0) -> DeviceKeyInfo:
    """
    Read the Device Key characteristic from a Hubble Ready device.

    Args:
        address: BLE address of the device
        timeout: Connection timeout in seconds (default: 30.0)

    Returns:
        DeviceKeyInfo with encryption mode and key size

    Raises:
        BleakError: If connection fails or read operation fails
    """
    try:
        return asyncio.run(_read_key_info_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_read_key_info_async(address, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )


async def _read_config_async(address: str, timeout: float = 30.0) -> DeviceConfig:
    """Async implementation of read_config."""
    async with BleakClient(address, timeout=timeout) as client:
        data = await client.read_gatt_char(CHAR_DEVICE_CONFIG_UUID)
        return DeviceConfig.from_bytes(bytes(data))


def read_config(address: str, timeout: float = 30.0) -> DeviceConfig:
    """
    Read the Device Configuration characteristic from a Hubble Ready device.

    Args:
        address: BLE address of the device
        timeout: Connection timeout in seconds (default: 30.0)

    Returns:
        DeviceConfig with eid_type, rotation_period, and pool_size

    Raises:
        BleakError: If connection fails or read operation fails
    """
    try:
        return asyncio.run(_read_config_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_read_config_async(address, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )


async def _read_time_async(address: str, timeout: float = 30.0) -> int:
    """Async implementation of read_time."""
    async with BleakClient(address, timeout=timeout) as client:
        data = await client.read_gatt_char(CHAR_EPOCH_TIME_UUID)
        return int.from_bytes(bytes(data), byteorder="little")


def read_time(address: str, timeout: float = 30.0) -> int:
    """
    Read the Epoch Time characteristic from a Hubble Ready device.

    Args:
        address: BLE address of the device
        timeout: Connection timeout in seconds (default: 30.0)

    Returns:
        Unix timestamp as integer

    Raises:
        BleakError: If connection fails or read operation fails
    """
    try:
        return asyncio.run(_read_time_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_read_time_async(address, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )


@dataclass(frozen=True)
class DeviceConfig:
    """Parsed Device Configuration characteristic (0x0004) data."""

    eid_type: str  # "utc" or "counter"
    eid_type_code: int  # 0x00 for UTC, 0x01 for Counter
    rotation_period: int  # Rotation period in seconds (should be 0)
    pool_size: int  # Pool size for counter mode (0 for UTC mode)
    raw_bytes: str  # Hex representation of raw bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "DeviceConfig":
        """Parse Device Configuration characteristic from raw bytes."""
        if len(data) < 12:
            raise ValueError(f"Device Configuration data too short: {len(data)} bytes, need 12")

        eid_type_code = data[0]
        if eid_type_code == 0x00:
            eid_type = "utc"
        elif eid_type_code == 0x01:
            eid_type = "counter"
        else:
            raise ValueError(f"Unknown EID type: 0x{eid_type_code:02x}")

        rotation_period = int.from_bytes(data[1:5], byteorder="little")
        pool_size = int.from_bytes(data[5:7], byteorder="little")
        raw_bytes = data.hex()

        return cls(
            eid_type=eid_type,
            eid_type_code=eid_type_code,
            rotation_period=rotation_period,
            pool_size=pool_size,
            raw_bytes=raw_bytes,
        )

    def to_display_string(self) -> str:
        """Return human-readable configuration string."""
        eid_str = "UTC-based EID" if self.eid_type == "utc" else "Counter-based EID"
        parts = [eid_str]
        if self.rotation_period > 0:
            parts.append(f"Rotation: {self.rotation_period}s")
        if self.eid_type == "counter":
            parts.append(f"Pool size: {self.pool_size}")
        return ", ".join(parts)


@dataclass
class WriteResult:
    """Result of a GATT characteristic write operation."""

    success: bool
    characteristic_name: str
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    duration_ms: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "success": self.success,
            "characteristic_name": self.characteristic_name,
            "duration_ms": self.duration_ms,
        }
        if self.error_code is not None:
            result["error_code"] = self.error_code
        if self.error_message is not None:
            result["error_message"] = self.error_message
        return result


@dataclass
class TestResult:
    """Result of an individual validation test."""

    name: str
    status: str  # "passed", "failed", "skipped"
    duration_ms: int = 0
    details: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "name": self.name,
            "status": self.status,
            "duration_ms": self.duration_ms,
        }
        if self.details is not None:
            result["details"] = self.details
        if self.error is not None:
            result["error"] = self.error
        return result


@dataclass
class ValidationResult:
    """Result of a validation test suite run."""

    device_address: str
    device_name: Optional[str]
    tests: List[TestResult]

    @property
    def summary(self) -> dict:
        """Calculate test statistics."""
        passed = sum(1 for t in self.tests if t.status == "passed")
        failed = sum(1 for t in self.tests if t.status == "failed")
        skipped = sum(1 for t in self.tests if t.status == "skipped")
        total = len(self.tests)
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        }

    @property
    def success(self) -> bool:
        """Return True if all tests passed."""
        return all(t.status == "passed" for t in self.tests)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "device_address": self.device_address,
            "device_name": self.device_name,
            "tests": [t.to_dict() for t in self.tests],
            "summary": self.summary,
            "success": self.success,
        }


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


# Device Information Service UUID (standard Bluetooth SIG)
DIS_SERVICE_UUID = "0000180a-0000-1000-8000-00805f9b34fb"
DIS_SERIAL_NUMBER_UUID = "00002a25-0000-1000-8000-00805f9b34fb"


@dataclass
class DeviceConfiguration:
    """Configuration to write to Device Configuration characteristic."""

    eid_type: int = 0x00  # 0x00 = UTC-based, 0x01 = Counter-based
    rotation_period: int = 0  # 0 = use device default
    eid_pool_size: int = 0  # Counter-mode only

    def to_bytes(self) -> bytes:
        """Serialize to 12-byte configuration data."""
        data = bytearray(12)
        data[0] = self.eid_type
        data[1:5] = self.rotation_period.to_bytes(4, byteorder="little")
        data[5:7] = self.eid_pool_size.to_bytes(2, byteorder="little")
        # bytes 7-11 are reserved (zeros)
        return bytes(data)


@dataclass
class ProvisioningResult:
    """Result of a provisioning operation."""

    success: bool
    device_id: str
    device_name: str
    device_key_base64: str
    encryption_type: str
    error_message: Optional[str] = None


async def _provision_device_async(
    address: str,
    org: "Organization",  # Forward reference to avoid circular import
    device_name: Optional[str] = None,
    scanned_device_name: Optional[str] = None,
    eid_type: str = "utc",
    timeout: float = 30.0,
    log_callback: Optional[callable] = None,
) -> ProvisioningResult:
    """
    Async implementation of full device provisioning flow.

    Steps:
    1. Connect to device
    2. Read Status - verify Open Mode
    3. Read Device Key - get supported encryption modes
    4. Read DIS Serial Number (for name fallback if needed)
    5. Register device with backend API
    6. Write Device Key
    7. Write Device Configuration
    8. Write Epoch Time
    9. Verify provisioning via Status read
    """
    import base64
    import time

    def log(msg: str) -> None:
        if log_callback:
            log_callback(msg)

    # Map EID type string to byte value
    eid_type_bytes = {
        "utc": 0x00,
        "counter": 0x01,
    }
    if eid_type not in eid_type_bytes:
        return ProvisioningResult(
            success=False,
            device_id="",
            device_name="",
            device_key_base64="",
            encryption_type="",
            error_message=f"Unsupported EID type: {eid_type}. Only 'utc' is currently supported.",
        )

    async with BleakClient(address, timeout=timeout) as client:
        log(f"Connected to {address}")

        # Step 1: Read Status
        log("Reading Status characteristic...")
        status_data = bytes(await client.read_gatt_char(CHAR_STATUS_UUID))
        status = StatusCharacteristic.from_bytes(status_data)
        log(f"  Version: {status.version_string}, {status.mode_string}")

        if status.is_locked:
            return ProvisioningResult(
                success=False,
                device_id="",
                device_name="",
                device_key_base64="",
                encryption_type="",
                error_message="Device is in Locked Mode. Open Mode required for provisioning.",
            )

        # Step 2: Determine device name
        # Priority: provided device_name > DIS serial number > scanned_device_name > generated name
        final_name = device_name
        if not final_name:
            # Try to read DIS Serial Number
            serial_number: Optional[str] = None
            try:
                log("Reading Device Information Service...")
                serial_data = bytes(await client.read_gatt_char(DIS_SERIAL_NUMBER_UUID))
                serial_number = serial_data.decode("utf-8").strip("\x00")
                log(f"  Serial Number: {serial_number}")
            except Exception:
                log("  Serial Number: Not available")

            if serial_number:
                final_name = serial_number
            elif scanned_device_name:
                final_name = scanned_device_name
            else:
                final_name = f"Device-{address[-5:].replace(':', '')}"

        # Step 3: Read Device Key (get device's supported encryption mode)
        log("Reading Device Key characteristic...")
        key_info_data = bytes(await client.read_gatt_char(CHAR_DEVICE_KEY_UUID))
        key_info = DeviceKeyInfo.from_bytes(key_info_data)
        encryption = key_info.encryption_mode
        log(f"  Device encryption mode: {encryption} ({key_info.key_size} bytes)")

        # Step 4: Register device with backend
        log("Registering device with Hubble backend...")
        registered_device = org.register_device(encryption=encryption)
        device_id = registered_device.id
        device_key = registered_device.key  # bytes
        device_key_base64 = base64.b64encode(device_key).decode("utf-8")
        log(f"  Device ID: {device_id}")

        # Verify backend returned correct key size
        if len(device_key) < key_info.key_size:
            return ProvisioningResult(
                success=False,
                device_id=device_id,
                device_name="",
                device_key_base64="",
                encryption_type=encryption,
                error_message=f"Backend returned {len(device_key)}-byte key, "
                             f"but device requires {key_info.key_size} bytes for {encryption}",
            )

        # Set device name
        log(f"  Setting name: {final_name}")
        org.set_device_name(device_id, final_name)

        # Step 5: Write Device Key (raw bytes only, no type prefix)
        key_size = key_info.key_size
        log(f"Writing device key ({key_size} bytes, {key_info.encryption_mode})...")

        # Write raw key bytes only (no encryption type prefix in new spec)
        key_write_data = device_key[:key_size]
        await client.write_gatt_char(CHAR_DEVICE_KEY_UUID, key_write_data)

        # Step 6: Write Device Configuration
        log(f"Writing device configuration (EID type: {eid_type})...")
        config = DeviceConfiguration(eid_type=eid_type_bytes[eid_type])
        await client.write_gatt_char(CHAR_DEVICE_CONFIG_UUID, config.to_bytes())

        # Step 7: Write Epoch Time
        current_time = int(time.time())
        log(f"Writing epoch time ({current_time})...")
        epoch_data = current_time.to_bytes(8, byteorder="little")
        await client.write_gatt_char(CHAR_EPOCH_TIME_UUID, epoch_data)

        # Step 8: Verify provisioning
        log("Verifying provisioning...")
        verify_data = bytes(await client.read_gatt_char(CHAR_STATUS_UUID))
        verify_status = StatusCharacteristic.from_bytes(verify_data)

        if not verify_status.key_written:
            return ProvisioningResult(
                success=False,
                device_id=device_id,
                device_name=final_name,
                device_key_base64=device_key_base64,
                encryption_type=encryption,
                error_message="Key write verification failed",
            )

        if not verify_status.config_written:
            return ProvisioningResult(
                success=False,
                device_id=device_id,
                device_name=final_name,
                device_key_base64=device_key_base64,
                encryption_type=encryption,
                error_message="Config write verification failed",
            )

        if not verify_status.epoch_time_written:
            return ProvisioningResult(
                success=False,
                device_id=device_id,
                device_name=final_name,
                device_key_base64=device_key_base64,
                encryption_type=encryption,
                error_message="Epoch time write verification failed",
            )

        log("Device provisioned successfully!")

    return ProvisioningResult(
        success=True,
        device_id=device_id,
        device_name=final_name,
        device_key_base64=device_key_base64,
        encryption_type=encryption,
    )


def provision_device(
    address: str,
    org: "Organization",
    device_name: Optional[str] = None,
    scanned_device_name: Optional[str] = None,
    eid_type: str = "utc",
    timeout: float = 30.0,
    log_callback: Optional[callable] = None,
) -> ProvisioningResult:
    """
    Provision a Hubble Ready device.

    This connects to the device, registers it with the Hubble backend, writes
    the encryption key and configuration, and verifies the provisioning.

    The encryption mode (AES-256-CTR or AES-128-CTR) is automatically detected
    from the device during provisioning.

    Args:
        address: BLE address of the device
        org: Organization object with valid credentials
        device_name: Optional name for the device (if not provided, falls back to other sources)
        scanned_device_name: Optional name from BLE scan advertisement
        eid_type: EID type ("utc" only currently supported)
        timeout: Connection timeout in seconds
        log_callback: Optional callback for progress messages

    Returns:
        ProvisioningResult with device ID, key, and status

    Name resolution priority:
        1. device_name (if provided)
        2. DIS Serial Number (read during provisioning)
        3. scanned_device_name (from BLE scan)
        4. Generated name based on address
    """
    try:
        return asyncio.run(
            _provision_device_async(
                address, org, device_name, scanned_device_name, eid_type, timeout, log_callback
            )
        )
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    _provision_device_async(
                        address, org, device_name, scanned_device_name, eid_type, timeout, log_callback
                    )
                )
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
