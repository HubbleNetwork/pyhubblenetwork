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


class TestFormatPayload:
    """Tests for the _format_payload helper."""

    def test_base64_encoding(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'\x01\x02\x03', "base64") == "AQID"

    def test_hex_encoding_uppercase(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'\xab\xc6\x79', "hex") == "ABC679"

    def test_hex_encoding_all_zeros(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'\x00\x00', "hex") == "0000"

    def test_string_encoding_valid_utf8(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'hello world', "string") == "hello world"

    def test_string_encoding_invalid_utf8_returns_fallback(self, capsys):
        from hubblenetwork.cli import _format_payload
        result = _format_payload(b'\xff\xfe', "string")
        assert result == "<invalid UTF-8>"

    def test_string_encoding_invalid_utf8_warns_to_stderr(self, capsys):
        from hubblenetwork.cli import _format_payload
        _format_payload(b'\xff\xfe', "string")
        captured = capsys.readouterr()
        assert "Warning" in captured.err

    def test_empty_bytes_base64(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'', "base64") == ""

    def test_empty_bytes_hex(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'', "hex") == ""

    def test_non_bytes_passthrough(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload("already a string", "base64") == "already a string"


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

    def test_encrypted_packet_payload_hex(self):
        from hubblenetwork.cli import _packet_to_dict
        raw = b'\xab\xc6\x79'
        pkt = make_encrypted_packet(raw)
        result = _packet_to_dict(pkt, payload_format="hex")
        assert result["payload"] == "ABC679"

    def test_decrypted_packet_payload_string(self):
        from hubblenetwork.cli import _packet_to_dict
        raw = b'sensor:42'
        pkt = make_decrypted_packet(raw)
        result = _packet_to_dict(pkt, payload_format="string")
        assert result["payload"] == "sensor:42"

    def test_decrypted_packet_payload_string_invalid_utf8(self, capsys):
        from hubblenetwork.cli import _packet_to_dict
        raw = b'\xff\xfe'
        pkt = make_decrypted_packet(raw)
        result = _packet_to_dict(pkt, payload_format="string")
        assert result["payload"] == "<invalid UTF-8>"
        captured = capsys.readouterr()
        assert "Warning" in captured.err


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


class TestStreamingTablePrinterPayloadFormat:
    """Tests for _StreamingTablePrinter with non-default payload formats."""

    def test_hex_format(self, capsys):
        from hubblenetwork.cli import _StreamingTablePrinter
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingTablePrinter(payload_format="hex")
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_string_format_valid_utf8(self, capsys):
        from hubblenetwork.cli import _StreamingTablePrinter
        raw = b'sensor:42'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingTablePrinter(payload_format="string")
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert "sensor:42" in captured.out

    def test_default_is_still_base64(self, capsys):
        from hubblenetwork.cli import _StreamingTablePrinter
        raw = b'\x01\x02\x03'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingTablePrinter()
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert base64.b64encode(raw).decode("ascii") in captured.out


class TestStreamingJsonPrinterPayloadFormat:
    """Tests for _StreamingJsonPrinter with non-default payload formats."""

    def test_hex_format(self, capsys):
        from hubblenetwork.cli import _StreamingJsonPrinter
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingJsonPrinter(payload_format="hex")
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_default_is_base64(self, capsys):
        from hubblenetwork.cli import _StreamingJsonPrinter
        raw = b'\x01\x02\x03'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingJsonPrinter()
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert base64.b64encode(raw).decode("ascii") in captured.out


class TestBatchPrinters:
    """Tests for _print_packets_* functions with payload_format."""

    def test_tabular_hex(self, capsys):
        from hubblenetwork.cli import _print_packets_tabular
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        _print_packets_tabular([pkt], payload_format="hex")
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_tabular_default_base64(self, capsys):
        from hubblenetwork.cli import _print_packets_tabular
        raw = b'\x01\x02\x03'
        pkt = make_decrypted_packet(raw)
        _print_packets_tabular([pkt])
        captured = capsys.readouterr()
        assert base64.b64encode(raw).decode("ascii") in captured.out

    def test_json_hex(self, capsys):
        from hubblenetwork.cli import _print_packets_json
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        _print_packets_json([pkt], payload_format="hex")
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_csv_hex(self, capsys):
        from hubblenetwork.cli import _print_packets_csv
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        _print_packets_csv([pkt], payload_format="hex")
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_csv_string(self, capsys):
        from hubblenetwork.cli import _print_packets_csv
        raw = b'temp:25'
        pkt = make_decrypted_packet(raw)
        _print_packets_csv([pkt], payload_format="string")
        captured = capsys.readouterr()
        assert "temp:25" in captured.out
