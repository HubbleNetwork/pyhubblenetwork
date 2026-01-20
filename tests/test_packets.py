"""Tests for packets.py dataclasses."""

from __future__ import annotations

import pytest
from dataclasses import FrozenInstanceError

from hubblenetwork.packets import Location, EncryptedPacket, DecryptedPacket


class TestLocation:
    """Tests for Location dataclass."""

    def test_create_with_required_fields(self):
        """Test creating Location with only required fields."""
        loc = Location(lat=37.7749, lon=-122.4194)
        assert loc.lat == 37.7749
        assert loc.lon == -122.4194
        assert loc.alt_m is None
        assert loc.fake is False

    def test_create_with_all_fields(self):
        """Test creating Location with all fields."""
        loc = Location(lat=37.7749, lon=-122.4194, alt_m=100.5, fake=True)
        assert loc.lat == 37.7749
        assert loc.lon == -122.4194
        assert loc.alt_m == 100.5
        assert loc.fake is True

    def test_frozen_immutability(self):
        """Test that Location is immutable (frozen dataclass)."""
        loc = Location(lat=37.7749, lon=-122.4194)
        with pytest.raises(FrozenInstanceError):
            loc.lat = 0.0

    def test_equality(self):
        """Test Location equality comparison."""
        loc1 = Location(lat=37.7749, lon=-122.4194)
        loc2 = Location(lat=37.7749, lon=-122.4194)
        loc3 = Location(lat=0.0, lon=0.0)
        assert loc1 == loc2
        assert loc1 != loc3

    def test_hash(self):
        """Test that Location is hashable (can be used in sets/dicts)."""
        loc1 = Location(lat=37.7749, lon=-122.4194)
        loc2 = Location(lat=37.7749, lon=-122.4194)
        locations = {loc1, loc2}
        assert len(locations) == 1


class TestEncryptedPacket:
    """Tests for EncryptedPacket dataclass."""

    def test_create_with_all_fields(self):
        """Test creating EncryptedPacket with all required fields."""
        loc = Location(lat=37.7749, lon=-122.4194)
        pkt = EncryptedPacket(
            timestamp=1700000000,
            location=loc,
            payload=b"\x00\x01\x02\x03",
            rssi=-70,
        )
        assert pkt.timestamp == 1700000000
        assert pkt.location == loc
        assert pkt.payload == b"\x00\x01\x02\x03"
        assert pkt.rssi == -70

    def test_create_with_none_location(self):
        """Test creating EncryptedPacket with None location."""
        pkt = EncryptedPacket(
            timestamp=1700000000,
            location=None,
            payload=b"\x00\x01\x02\x03",
            rssi=-70,
        )
        assert pkt.location is None

    def test_frozen_immutability(self):
        """Test that EncryptedPacket is immutable."""
        pkt = EncryptedPacket(
            timestamp=1700000000,
            location=None,
            payload=b"\x00\x01\x02\x03",
            rssi=-70,
        )
        with pytest.raises(FrozenInstanceError):
            pkt.timestamp = 0

    def test_equality(self):
        """Test EncryptedPacket equality comparison."""
        pkt1 = EncryptedPacket(
            timestamp=1700000000,
            location=None,
            payload=b"\x00\x01\x02\x03",
            rssi=-70,
        )
        pkt2 = EncryptedPacket(
            timestamp=1700000000,
            location=None,
            payload=b"\x00\x01\x02\x03",
            rssi=-70,
        )
        assert pkt1 == pkt2


class TestDecryptedPacket:
    """Tests for DecryptedPacket dataclass."""

    def test_create_with_required_fields(self):
        """Test creating DecryptedPacket with required fields."""
        loc = Location(lat=37.7749, lon=-122.4194)
        pkt = DecryptedPacket(
            timestamp=1700000000,
            device_id="dev-123",
            device_name="Test Device",
            location=loc,
            tags={"env": "test"},
            payload=b"Hello",
            rssi=-65,
        )
        assert pkt.timestamp == 1700000000
        assert pkt.device_id == "dev-123"
        assert pkt.device_name == "Test Device"
        assert pkt.location == loc
        assert pkt.tags == {"env": "test"}
        assert pkt.payload == b"Hello"
        assert pkt.rssi == -65
        assert pkt.counter is None
        assert pkt.sequence is None

    def test_create_with_optional_fields(self):
        """Test creating DecryptedPacket with all optional fields."""
        pkt = DecryptedPacket(
            timestamp=1700000000,
            device_id="dev-123",
            device_name="Test Device",
            location=None,
            tags={},
            payload=b"Hello",
            rssi=-65,
            counter=20000,
            sequence=42,
        )
        assert pkt.counter == 20000
        assert pkt.sequence == 42

    def test_frozen_immutability(self):
        """Test that DecryptedPacket is immutable."""
        pkt = DecryptedPacket(
            timestamp=1700000000,
            device_id="dev-123",
            device_name="Test Device",
            location=None,
            tags={},
            payload=b"Hello",
            rssi=-65,
        )
        with pytest.raises(FrozenInstanceError):
            pkt.device_id = "other"

    def test_with_empty_tags(self):
        """Test DecryptedPacket with empty tags dict."""
        pkt = DecryptedPacket(
            timestamp=1700000000,
            device_id="dev-123",
            device_name="",
            location=None,
            tags={},
            payload=b"",
            rssi=0,
        )
        assert pkt.tags == {}
        assert pkt.device_name == ""
        assert pkt.payload == b""
