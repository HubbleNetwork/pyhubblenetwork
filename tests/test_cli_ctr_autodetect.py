"""CLI auto-detect tests for AES-CTR (counter_source) in `ble scan`."""
from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from hubblenetwork.cli import cli
from hubblenetwork.packets import DecryptedPacket, EncryptedPacket, Location

from tests.test_counter_eid import _encrypt_payload


_FAKE_LOC = Location(lat=0.0, lon=0.0, fake=True)


def _make_ctr_packet_with_eid(key: bytes, counter: int, seq_no: int, plaintext: bytes, eid: int) -> EncryptedPacket:
    payload = _encrypt_payload(key, counter, seq_no, plaintext)
    return EncryptedPacket(
        timestamp=1700000000,
        location=_FAKE_LOC,
        payload=payload,
        rssi=-70,
        protocol_version=0,
        eid=eid,
        auth_tag=payload[6:10],
    )


def _decrypted(payload: bytes = b"d", counter: int = 1, seq_no: int = 1) -> DecryptedPacket:
    return DecryptedPacket(
        timestamp=1700000000,
        device_id="",
        device_name="",
        location=_FAKE_LOC,
        tags={},
        payload=payload,
        rssi=-70,
        counter=counter,
        sequence=seq_no,
    )


_KEY_256_HEX = bytes(range(32)).hex()
_KEY_128_HEX = bytes(range(16)).hex()


class TestCliCtrAutoDetect:
    @patch("hubblenetwork.cli.decrypt")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_finds_unix_time(self, mock_scan, mock_decrypt):
        """UNIX_TIME succeeds on first try → banner names UNIX_TIME."""
        pkt = _make_ctr_packet_with_eid(bytes(range(32)), 0, 1, b"x", eid=0xAB)
        mock_scan.side_effect = [pkt, None]
        mock_decrypt.side_effect = lambda key, p, **kw: (
            _decrypted() if kw.get("counter_mode") == "UNIX_TIME" else None
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "--key", _KEY_256_HEX])
        assert result.exit_code == 0
        assert "[INFO] Detected: AES-256-CTR, counter_source=UNIX_TIME" in result.stderr

    @patch("hubblenetwork.cli.decrypt")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_finds_device_uptime(self, mock_scan, mock_decrypt):
        """UNIX_TIME fails, DEVICE_UPTIME succeeds → banner names DEVICE_UPTIME."""
        pkt = _make_ctr_packet_with_eid(bytes(range(32)), 0, 1, b"x", eid=0xAB)
        mock_scan.side_effect = [pkt, None]
        mock_decrypt.side_effect = lambda key, p, **kw: (
            _decrypted() if kw.get("counter_mode") == "DEVICE_UPTIME" else None
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "--key", _KEY_256_HEX])
        assert result.exit_code == 0
        assert "[INFO] Detected: AES-256-CTR, counter_source=DEVICE_UPTIME" in result.stderr

    @patch("hubblenetwork.cli.decrypt")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_caches_per_eid(self, mock_scan, mock_decrypt):
        """Two packets with same EID: detect on first, cache hit on second."""
        pkt = _make_ctr_packet_with_eid(bytes(range(32)), 0, 1, b"x", eid=0xCAFE)
        mock_scan.side_effect = [pkt, pkt, None]

        # DEVICE_UPTIME succeeds; UNIX_TIME fails (so we exercise both modes
        # on first packet and only DEVICE_UPTIME on the cached second packet).
        mock_decrypt.side_effect = lambda key, p, **kw: (
            _decrypted() if kw.get("counter_mode") == "DEVICE_UPTIME" else None
        )

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "--key", _KEY_256_HEX])
        assert result.exit_code == 0
        # First packet: 2 calls (UNIX_TIME fail, DEVICE_UPTIME success).
        # Second packet: 1 call via cache (DEVICE_UPTIME).
        modes_called = [c.kwargs.get("counter_mode") for c in mock_decrypt.call_args_list]
        assert modes_called == ["UNIX_TIME", "DEVICE_UPTIME", "DEVICE_UPTIME"]
        # Detection banner emitted exactly once.
        assert result.stderr.count("[INFO] Detected:") == 1

    @patch("hubblenetwork.cli.decrypt")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_no_warn_when_counter_mode_provided(self, mock_scan, mock_decrypt):
        """Explicit --counter-mode + -e disables both auto-detect axes."""
        pkt = _make_ctr_packet_with_eid(bytes(range(32)), 0, 1, b"x", eid=0xAB)
        mock_scan.side_effect = [pkt, None]
        mock_decrypt.return_value = _decrypted()

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "scan", "--timeout", "1",
                "--key", _KEY_256_HEX,
                "--counter-mode", "UNIX_TIME",
                "-e", "0",
            ],
        )
        assert result.exit_code == 0
        assert "[WARN]" not in result.stderr
        assert "[INFO] Detected:" not in result.stderr
        # decrypt() was called without the auto-detect probe (just once).
        assert mock_decrypt.call_count == 1

    @patch("hubblenetwork.cli.decrypt")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_reports_correct_key_size(self, mock_scan, mock_decrypt):
        """Banner labels AES-128-CTR for a 16-byte key."""
        pkt = _make_ctr_packet_with_eid(bytes(range(16)), 0, 1, b"x", eid=0xAB)
        mock_scan.side_effect = [pkt, None]
        mock_decrypt.side_effect = lambda key, p, **kw: _decrypted()

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "--key", _KEY_128_HEX])
        assert result.exit_code == 0
        assert "[INFO] Detected: AES-128-CTR, counter_source=UNIX_TIME" in result.stderr
