import base64
import pytest
from unittest.mock import MagicMock
from hubblenetwork.packets import EncryptedPacket, DecryptedPacket
from hubblenetwork.packets import Location


def fake_location():
    loc = MagicMock(spec=Location)
    loc.fake = True
    loc.lat = 0.0
    loc.lon = 0.0
    return loc


def make_encrypted_packet(payload: bytes) -> EncryptedPacket:
    return EncryptedPacket(
        timestamp=1700000000,
        location=fake_location(),
        payload=payload,
        rssi=-70,
    )


def make_decrypted_packet(payload: bytes) -> DecryptedPacket:
    return DecryptedPacket(
        timestamp=1700000000,
        device_id="dev123",
        device_name="Test Device",
        location=fake_location(),
        tags={},
        payload=payload,
        rssi=-70,
        counter=42,
        sequence=1,
    )


class TestPacketToDict:
    """Tests for _packet_to_dict payload encoding."""

    def test_encrypted_packet_payload_is_base64(self):
        from hubblenetwork.cli import _packet_to_dict
        raw = b'\x01\x02\x03\xff'
        pkt = make_encrypted_packet(raw)
        result = _packet_to_dict(pkt)
        assert "payload" in result
        assert result["payload"] == base64.b64encode(raw).decode("ascii")
        assert "payload_hex" not in result

    def test_decrypted_packet_payload_is_base64(self):
        from hubblenetwork.cli import _packet_to_dict
        raw = b'\xde\xad\xbe\xef'
        pkt = make_decrypted_packet(raw)
        result = _packet_to_dict(pkt)
        assert "payload" in result
        assert result["payload"] == base64.b64encode(raw).decode("ascii")
        assert "payload_hex" not in result

    def test_decrypted_packet_utf8_payload_still_base64(self):
        """Even valid UTF-8 should be base64 encoded."""
        from hubblenetwork.cli import _packet_to_dict
        raw = b'hello world'
        pkt = make_decrypted_packet(raw)
        result = _packet_to_dict(pkt)
        assert result["payload"] == base64.b64encode(raw).decode("ascii")

    def test_empty_payload_is_base64(self):
        from hubblenetwork.cli import _packet_to_dict
        pkt = make_encrypted_packet(b'')
        result = _packet_to_dict(pkt)
        assert result["payload"] == ""


class TestStreamingTablePrinter:
    """Tests for tabular payload display."""

    def test_table_row_payload_is_base64(self, capsys):
        from hubblenetwork.cli import _StreamingTablePrinter
        raw = b'\x01\x02\x03'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingTablePrinter()
        printer.print_row(pkt)
        captured = capsys.readouterr()
        expected_b64 = base64.b64encode(raw).decode("ascii")
        assert expected_b64 in captured.out
