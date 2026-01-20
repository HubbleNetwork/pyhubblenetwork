"""Tests for device.py Device model."""

from __future__ import annotations

import pytest

from hubblenetwork.device import Device


class TestDevice:
    """Tests for Device dataclass."""

    def test_create_with_id_only(self):
        """Test creating Device with only required id field."""
        dev = Device(id="dev-123")
        assert dev.id == "dev-123"
        assert dev.key is None
        assert dev.name is None
        assert dev.tags is None
        assert dev.created_ts is None
        assert dev.active is False

    def test_create_with_all_fields(self):
        """Test creating Device with all fields."""
        dev = Device(
            id="dev-123",
            key=b"\x00" * 32,
            name="Test Device",
            tags={"type": "sensor"},
            created_ts=1700000000,
            active=True,
        )
        assert dev.id == "dev-123"
        assert dev.key == b"\x00" * 32
        assert dev.name == "Test Device"
        assert dev.tags == {"type": "sensor"}
        assert dev.created_ts == 1700000000
        assert dev.active is True

    def test_device_is_mutable(self):
        """Test that Device is mutable (not frozen)."""
        dev = Device(id="dev-123", name="Original")
        dev.name = "Updated"
        assert dev.name == "Updated"

    def test_from_json_complete(self):
        """Test from_json with complete JSON data."""
        json_data = {
            "id": "dev-abc-123",
            "name": "JSON Device",
            "tags": {"env": "prod"},
            "created_ts": 1700000000,
            "active": True,
        }
        dev = Device.from_json(json_data)
        assert dev.id == "dev-abc-123"
        assert dev.name == "JSON Device"
        assert dev.tags == {"env": "prod"}
        assert dev.created_ts == 1700000000
        assert dev.active is True

    def test_from_json_partial(self):
        """Test from_json with partial JSON data."""
        json_data = {"id": "dev-minimal"}
        dev = Device.from_json(json_data)
        assert dev.id == "dev-minimal"
        assert dev.name is None
        assert dev.tags is None
        assert dev.created_ts is None
        assert dev.active is None

    def test_from_json_id_conversion(self):
        """Test from_json converts id to string."""
        json_data = {"id": 12345}
        dev = Device.from_json(json_data)
        assert dev.id == "12345"
        assert isinstance(dev.id, str)

    def test_from_json_missing_id(self):
        """Test from_json with missing id raises KeyError or returns 'None' string."""
        json_data = {"name": "No ID Device"}
        dev = Device.from_json(json_data)
        # str(None) returns "None"
        assert dev.id == "None"

    def test_from_json_key_not_included(self):
        """Test that from_json doesn't set key (keys come from different endpoint)."""
        json_data = {
            "id": "dev-123",
            "key": "should_be_ignored",  # Not extracted by from_json
        }
        dev = Device.from_json(json_data)
        assert dev.key is None  # from_json doesn't extract key

    def test_equality(self):
        """Test Device equality is based on all fields."""
        dev1 = Device(id="dev-123", name="Test")
        dev2 = Device(id="dev-123", name="Test")
        dev3 = Device(id="dev-123", name="Different")
        assert dev1 == dev2
        assert dev1 != dev3

    def test_with_128_bit_key(self):
        """Test Device with 128-bit (16 byte) key."""
        dev = Device(id="dev-123", key=b"\x00" * 16)
        assert len(dev.key) == 16

    def test_with_256_bit_key(self):
        """Test Device with 256-bit (32 byte) key."""
        dev = Device(id="dev-123", key=b"\xff" * 32)
        assert len(dev.key) == 32
