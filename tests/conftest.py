"""Shared fixtures for hubblenetwork tests."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from typing import List

from hubblenetwork.packets import Location, EncryptedPacket, DecryptedPacket
from hubblenetwork.device import Device
from hubblenetwork.cloud import Credentials, Environment


# Sample test data
@pytest.fixture
def sample_location() -> Location:
    """A sample Location with real coordinates."""
    return Location(lat=37.7749, lon=-122.4194, alt_m=10.0, fake=False)


@pytest.fixture
def fake_location() -> Location:
    """A fake Location (used when location is unknown)."""
    return Location(lat=90.0, lon=0.0, fake=True)


@pytest.fixture
def sample_encrypted_packet(fake_location) -> EncryptedPacket:
    """A sample encrypted packet with test payload."""
    return EncryptedPacket(
        timestamp=1700000000,
        location=fake_location,
        payload=b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        rssi=-70,
    )


@pytest.fixture
def sample_decrypted_packet(sample_location) -> DecryptedPacket:
    """A sample decrypted packet."""
    return DecryptedPacket(
        timestamp=1700000000,
        device_id="test-device-123",
        device_name="Test Device",
        location=sample_location,
        tags={"env": "test"},
        payload=b"Hello, World!",
        rssi=-65,
        counter=20000,
        sequence=42,
    )


@pytest.fixture
def sample_device() -> Device:
    """A sample Device object."""
    return Device(
        id="dev-abc-123",
        key=b"\x00" * 32,  # 256-bit key
        name="Test Device",
        tags={"type": "sensor"},
        created_ts=1700000000,
        active=True,
    )


@pytest.fixture
def sample_credentials() -> Credentials:
    """Sample credentials for testing."""
    return Credentials(org_id="test-org-id", api_token="test-api-token")


@pytest.fixture
def sample_environment() -> Environment:
    """Sample environment for testing."""
    return Environment(name="TEST", url="https://api-test.example.com")


@pytest.fixture
def mock_httpx_client():
    """Mock httpx.Client for testing cloud requests."""
    with patch("hubblenetwork.cloud.httpx.Client") as mock_client:
        yield mock_client


@pytest.fixture
def mock_bleak_scanner():
    """Mock BleakScanner for testing BLE operations."""
    with patch("hubblenetwork.ble.BleakScanner") as mock_scanner:
        yield mock_scanner
