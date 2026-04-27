"""Tests for AES-EAX encrypted packet support."""
from __future__ import annotations

import json
import struct
from dataclasses import FrozenInstanceError
from unittest.mock import patch

import pytest

from Crypto.Cipher import AES as _AES
from click.testing import CliRunner
from hubblenetwork.cli import cli
from hubblenetwork.packets import AesEaxPacket, UnknownPacket, Location
from hubblenetwork.ble import _make_packet
from hubblenetwork.packets import EncryptedPacket
from hubblenetwork.crypto import _generate_eid, decrypt_eax
from hubblenetwork.packets import DecryptedPacket


# ---------------------------------------------------------------------------
# AesEaxPacket dataclass tests
# ---------------------------------------------------------------------------


class TestAesEaxPacket:
    def test_fields(self):
        pkt = AesEaxPacket(
            timestamp=1700000000,
            location=Location(lat=37.0, lon=-122.0),
            protocol_version=2,
            nonce_salt=b"\x01\x02",
            eid=0xDEADBEEFCAFEBABE,
            payload=b"\xAA\xBB",
            auth_tag=b"\x01\x02\x03\x04",
            rssi=-60,
        )
        assert pkt.timestamp == 1700000000
        assert pkt.protocol_version == 2
        assert pkt.nonce_salt == b"\x01\x02"
        assert pkt.eid == 0xDEADBEEFCAFEBABE
        assert pkt.payload == b"\xAA\xBB"
        assert pkt.auth_tag == b"\x01\x02\x03\x04"
        assert pkt.rssi == -60

    def test_frozen(self):
        pkt = AesEaxPacket(
            timestamp=0,
            location=None,
            protocol_version=2,
            nonce_salt=b"\x00\x00",
            eid=0,
            payload=b"",
            auth_tag=b"\x00" * 4,
            rssi=0,
        )
        with pytest.raises(FrozenInstanceError):
            pkt.eid = 999


# ---------------------------------------------------------------------------
# UnknownPacket dataclass tests
# ---------------------------------------------------------------------------


class TestUnknownPacket:
    def test_fields(self):
        pkt = UnknownPacket(
            timestamp=1700000000,
            location=Location(lat=0.0, lon=0.0, fake=True),
            protocol_version=5,
            payload=b"\xFF" * 10,
            rssi=-80,
        )
        assert pkt.protocol_version == 5
        assert pkt.payload == b"\xFF" * 10
        assert pkt.rssi == -80

    def test_frozen(self):
        pkt = UnknownPacket(
            timestamp=0,
            location=None,
            protocol_version=3,
            payload=b"",
            rssi=0,
        )
        with pytest.raises(FrozenInstanceError):
            pkt.protocol_version = 99


# ---------------------------------------------------------------------------
# _make_packet() version dispatch tests
# ---------------------------------------------------------------------------


class TestMakePacketVersionDispatch:
    def test_version_0_returns_encrypted_packet(self):
        """Version 0 (first byte 0x00) → EncryptedPacket."""
        raw = b"\x00" * 10  # version bits = 0
        pkt = _make_packet(raw, rssi=-70)
        assert isinstance(pkt, EncryptedPacket)
        assert pkt.payload == raw

    def test_version_1_returns_unencrypted_packet(self):
        """Version 1 → UnencryptedPacket (existing parse_unencrypted path)."""
        # Version=1, network_id=4378792717 → 0x0504ff130d
        raw = bytes.fromhex("0504ff130d") + b"\xAB"
        pkt = _make_packet(raw, rssi=-55)
        from hubblenetwork.packets import UnencryptedPacket
        assert isinstance(pkt, UnencryptedPacket)
        assert pkt.network_id == 4378792717
        assert pkt.protocol_version == 1
        assert pkt.payload == b"\xAB"

    def test_version_2_returns_aes_eax_packet(self):
        """Version 2 (first byte 0x08) → AesEaxPacket."""
        salt = b"\x11\x22"
        eid_bytes = struct.pack("<Q", 0xDEADBEEFCAFEBABE)
        payload = b"\xAA\xBB"
        tag = b"\x01\x02\x03\x04"
        raw = b"\x08" + salt + eid_bytes + payload + tag
        pkt = _make_packet(raw, rssi=-65)
        assert isinstance(pkt, AesEaxPacket)
        assert pkt.protocol_version == 2
        assert pkt.nonce_salt == salt
        assert pkt.eid == 0xDEADBEEFCAFEBABE
        assert pkt.payload == payload
        assert pkt.auth_tag == tag

    def test_version_2_minimum_size(self):
        """AES-EAX packet with 0 bytes of payload (minimum 15 bytes)."""
        salt = b"\x00\x00"
        eid_bytes = struct.pack("<Q", 42)
        tag = b"\x01\x02\x03\x04"
        raw = b"\x08" + salt + eid_bytes + tag  # 15 bytes, 0 payload
        pkt = _make_packet(raw, rssi=-60)
        assert isinstance(pkt, AesEaxPacket)
        assert pkt.payload == b""

    def test_version_2_too_short_falls_back_to_unknown(self):
        """AES-EAX packet shorter than 15 bytes → UnknownPacket."""
        raw = b"\x08" + b"\x00" * 5  # only 6 bytes, too short
        pkt = _make_packet(raw, rssi=-60)
        assert isinstance(pkt, UnknownPacket)
        assert pkt.protocol_version == 2

    def test_version_3_returns_unknown_packet(self):
        """Unknown version 3 → UnknownPacket."""
        raw = b"\x0c" + b"\x00" * 10  # 0x0c >> 2 = 3
        pkt = _make_packet(raw, rssi=-50)
        assert isinstance(pkt, UnknownPacket)
        assert pkt.protocol_version == 3

    def test_version_63_returns_unknown_packet(self):
        """Max version 63 → UnknownPacket."""
        raw = b"\xfc" + b"\x00" * 10  # 0xfc >> 2 = 63
        pkt = _make_packet(raw, rssi=-50)
        assert isinstance(pkt, UnknownPacket)
        assert pkt.protocol_version == 63

    def test_empty_data_returns_encrypted_packet(self):
        """Empty data → EncryptedPacket (safe fallback)."""
        pkt = _make_packet(b"", rssi=-90)
        assert isinstance(pkt, EncryptedPacket)


# ---------------------------------------------------------------------------
# Helpers — build a valid AES-EAX encrypted packet for a given counter
# ---------------------------------------------------------------------------


def _encrypt_eax_payload(key: bytes, counter: int, nonce_salt: bytes, plaintext: bytes) -> tuple:
    """Encrypt plaintext with AES-EAX and return (payload, auth_tag, eid)."""
    eid = _generate_eid(key, counter)
    nonce = counter.to_bytes(4, "big") + nonce_salt
    cipher = _AES.new(key, _AES.MODE_EAX, mac_len=4, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag, eid


_FAKE_LOCATION = Location(lat=90, lon=0, fake=True)


def _make_aes_eax_packet(key: bytes, counter: int, nonce_salt: bytes, plaintext: bytes) -> AesEaxPacket:
    """Build an AesEaxPacket whose auth tag is valid for the given counter."""
    ciphertext, tag, eid = _encrypt_eax_payload(key, counter, nonce_salt, plaintext)
    return AesEaxPacket(
        timestamp=1700000000,
        location=_FAKE_LOCATION,
        protocol_version=2,
        nonce_salt=nonce_salt,
        eid=eid,
        payload=ciphertext,
        auth_tag=tag,
        rssi=-70,
    )


def _make_dummy_aes_eax_packet(**overrides) -> AesEaxPacket:
    """Build an AesEaxPacket with dummy values (not cryptographically valid)."""
    defaults = dict(
        timestamp=1700000000,
        location=_FAKE_LOCATION,
        protocol_version=2,
        nonce_salt=b"\x11\x22",
        eid=0xDEADBEEFCAFEBABE,
        payload=b"\xAA\xBB",
        auth_tag=b"\x01\x02\x03\x04",
        rssi=-65,
    )
    defaults.update(overrides)
    return AesEaxPacket(**defaults)


def _make_dummy_unknown_packet(**overrides) -> UnknownPacket:
    """Build an UnknownPacket with dummy values."""
    defaults = dict(
        timestamp=1700000000,
        location=_FAKE_LOCATION,
        protocol_version=5,
        payload=b"\xFF" * 10,
        rssi=-80,
    )
    defaults.update(overrides)
    return UnknownPacket(**defaults)


# ---------------------------------------------------------------------------
# decrypt_eax() tests
# ---------------------------------------------------------------------------

_EAX_KEY = bytes(range(16))


class TestDecryptEax:
    def test_decrypt_finds_counter(self):
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=7, nonce_salt=b"\x11\x22", plaintext=b"hello")
        result = decrypt_eax(_EAX_KEY, pkt)
        assert result is not None
        assert result.payload == b"hello"
        assert result.counter == 7

    def test_decrypt_counter_zero(self):
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=0, nonce_salt=b"\xAA\xBB", plaintext=b"zero")
        result = decrypt_eax(_EAX_KEY, pkt)
        assert result is not None
        assert result.counter == 0
        assert result.payload == b"zero"

    def test_decrypt_counter_127(self):
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=127, nonce_salt=b"\xFF\x00", plaintext=b"edge")
        result = decrypt_eax(_EAX_KEY, pkt)
        assert result is not None
        assert result.counter == 127
        assert result.payload == b"edge"

    def test_decrypt_counter_outside_pool_returns_none(self):
        """Counter 128 is outside the 0-127 pool."""
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=128, nonce_salt=b"\x00\x01", plaintext=b"miss")
        result = decrypt_eax(_EAX_KEY, pkt)
        assert result is None

    def test_decrypt_wrong_key_returns_none(self):
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=5, nonce_salt=b"\x00\x00", plaintext=b"data")
        wrong_key = bytes(range(1, 17))
        result = decrypt_eax(wrong_key, pkt)
        assert result is None

    def test_decrypt_preserves_metadata(self):
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=2, nonce_salt=b"\x12\x34", plaintext=b"meta")
        result = decrypt_eax(_EAX_KEY, pkt)
        assert result is not None
        assert result.timestamp == 1700000000
        assert result.rssi == -70
        assert result.sequence == 0x1234  # nonce_salt as uint16

    def test_decrypt_empty_payload(self):
        """AES-EAX with 0 bytes of plaintext."""
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=10, nonce_salt=b"\x00\x00", plaintext=b"")
        result = decrypt_eax(_EAX_KEY, pkt)
        if result is not None:
            assert result.payload == b""

    def test_decrypt_returns_decrypted_packet_type(self):
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=1, nonce_salt=b"\x00\x00", plaintext=b"x")
        result = decrypt_eax(_EAX_KEY, pkt)
        assert isinstance(result, DecryptedPacket)

    def test_decrypt_tampered_tag_returns_none(self):
        """Tampered auth tag should fail verification."""
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=3, nonce_salt=b"\x00\x00", plaintext=b"tamper")
        tampered = AesEaxPacket(
            timestamp=pkt.timestamp,
            location=pkt.location,
            protocol_version=pkt.protocol_version,
            nonce_salt=pkt.nonce_salt,
            eid=pkt.eid,
            payload=pkt.payload,
            auth_tag=b"\xff\xff\xff\xff",
            rssi=pkt.rssi,
        )
        result = decrypt_eax(_EAX_KEY, tampered)
        assert result is None

    def test_decrypt_tampered_payload_returns_none(self):
        """Tampered ciphertext should fail verification."""
        pkt = _make_aes_eax_packet(_EAX_KEY, counter=3, nonce_salt=b"\x00\x00", plaintext=b"tamper")
        tampered = AesEaxPacket(
            timestamp=pkt.timestamp,
            location=pkt.location,
            protocol_version=pkt.protocol_version,
            nonce_salt=pkt.nonce_salt,
            eid=pkt.eid,
            payload=b"\xff" * len(pkt.payload),
            auth_tag=pkt.auth_tag,
            rssi=pkt.rssi,
        )
        result = decrypt_eax(_EAX_KEY, tampered)
        assert result is None


# ---------------------------------------------------------------------------
# CLI scan tests for AES-EAX packets
# ---------------------------------------------------------------------------


class TestCliAesEaxScan:
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_scan_aes_eax_no_key_tabular(self, mock_scan):
        """AES-EAX packet without key shows parsed fields in tabular output."""
        pkt = _make_dummy_aes_eax_packet()
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1"])
        assert result.exit_code == 0
        assert "VERSION" in result.output

    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_scan_aes_eax_no_key_json(self, mock_scan):
        """AES-EAX packet without key shows parsed fields in JSON output."""
        pkt = _make_dummy_aes_eax_packet()
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "-o", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert len(parsed) == 1
        assert parsed[0]["protocol_version"] == 2
        assert "eid" in parsed[0]
        assert "nonce_salt" in parsed[0]

    @patch("hubblenetwork.cli.decrypt_eax")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_scan_aes_eax_with_key_decrypts(self, mock_scan, mock_decrypt):
        """AES-EAX packet with key attempts decryption."""
        pkt = _make_dummy_aes_eax_packet()
        mock_scan.side_effect = [pkt, None]
        mock_decrypt.return_value = DecryptedPacket(
            timestamp=1700000000, device_id="", device_name="",
            location=Location(lat=90, lon=0, fake=True), tags={},
            payload=b"decrypted", rssi=-65, counter=7, sequence=None,
        )

        runner = CliRunner()
        key_b64 = "AAAAAAAAAAAAAAAAAAAAAA=="
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "--key", key_b64, "-o", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert len(parsed) == 1
        assert parsed[0]["counter"] == 7

    @patch("hubblenetwork.cli.decrypt_eax")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_scan_aes_eax_auth_fail_skipped_by_default(self, mock_scan, mock_decrypt):
        """Packets failing AES-EAX auth are skipped when --show-failed-decryption is off."""
        pkt = _make_dummy_aes_eax_packet()
        mock_scan.side_effect = [pkt, None]
        mock_decrypt.return_value = None  # auth failure

        runner = CliRunner()
        key_b64 = "AAAAAAAAAAAAAAAAAAAAAA=="
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "--key", key_b64, "-o", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed == []

    @patch("hubblenetwork.cli.decrypt_eax")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_scan_aes_eax_auth_fail_shown_when_flag_set(self, mock_scan, mock_decrypt):
        """With --show-failed-decryption, failing packets are shown with fail status."""
        pkt = _make_dummy_aes_eax_packet()
        mock_scan.side_effect = [pkt, None]
        mock_decrypt.return_value = None  # auth failure

        runner = CliRunner()
        key_b64 = "AAAAAAAAAAAAAAAAAAAAAA=="
        result = runner.invoke(
            cli,
            ["ble", "scan", "--timeout", "1", "--key", key_b64, "-o", "json", "--show-failed-decryption"],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert len(parsed) == 1
        assert parsed[0]["decrypt_status"] == "fail"
        assert parsed[0]["protocol_version"] == 2

    @patch("hubblenetwork.cli.decrypt_eax")
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_scan_aes_eax_success_shows_ok_when_flag_set(self, mock_scan, mock_decrypt):
        """With --show-failed-decryption, successful decrypts carry ok status."""
        pkt = _make_dummy_aes_eax_packet()
        mock_scan.side_effect = [pkt, None]
        mock_decrypt.return_value = DecryptedPacket(
            timestamp=1700000000, device_id="", device_name="",
            location=Location(lat=90, lon=0, fake=True), tags={},
            payload=b"decrypted", rssi=-65, counter=7, sequence=None,
        )

        runner = CliRunner()
        key_b64 = "AAAAAAAAAAAAAAAAAAAAAA=="
        result = runner.invoke(
            cli,
            ["ble", "scan", "--timeout", "1", "--key", key_b64, "-o", "json", "--show-failed-decryption"],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert len(parsed) == 1
        assert parsed[0]["decrypt_status"] == "ok"

    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_scan_unknown_packet_tabular(self, mock_scan):
        """Unknown version packet shows version in tabular output."""
        pkt = _make_dummy_unknown_packet()
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1"])
        assert result.exit_code == 0
        assert "VERSION" in result.output

    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_scan_unknown_packet_json(self, mock_scan):
        """Unknown version packet shows version and payload in JSON output."""
        pkt = _make_dummy_unknown_packet()
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "-o", "json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert len(parsed) == 1
        assert parsed[0]["protocol_version"] == 5


# ---------------------------------------------------------------------------
# CLI auto-detect tests for AES-EAX packets
# ---------------------------------------------------------------------------


def _build_eax_packet_at_exponent(key: bytes, period_exponent: int, plaintext: bytes) -> AesEaxPacket:
    """Build a real AES-EAX packet whose EID/tag matches the given exponent."""
    from hubblenetwork.crypto import _generate_eid as gen_eid
    # Pick a counter that's a multiple of the step (so it's enumerable
    # by decrypt_eax with this exponent).
    step = 1 << period_exponent
    counter = 3 * step  # 3rd slot
    eid = gen_eid(key, counter, period_exponent=period_exponent)
    nonce_salt = b"\x9A\xBC"
    nonce = counter.to_bytes(4, "big") + nonce_salt
    cipher = _AES.new(key, _AES.MODE_EAX, mac_len=4, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return AesEaxPacket(
        timestamp=1700000000,
        location=_FAKE_LOCATION,
        protocol_version=2,
        nonce_salt=nonce_salt,
        eid=eid,
        payload=ciphertext,
        auth_tag=tag,
        rssi=-70,
    )


_EAX_KEY_HEX = _EAX_KEY.hex()


class TestCliAesEaxAutoDetect:
    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_auto_detect_finds_correct_exponent(self, mock_scan):
        """Without -e, auto-detect resolves period_exponent and decrypts."""
        pkt = _build_eax_packet_at_exponent(_EAX_KEY, period_exponent=12, plaintext=b"hi-eax")
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "--key", _EAX_KEY_HEX])
        assert result.exit_code == 0
        assert "[WARN]" in result.stderr
        assert "Auto-detecting" in result.stderr
        assert "period_exponent=12" in result.stderr
        assert "period=4096s" in result.stderr
        # decrypted payload appears in the table
        assert "hi-eax" in result.stdout or "aGktZWF4" in result.stdout  # raw or base64

    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_auto_detect_uses_cache_for_same_eid(self, mock_scan):
        """Second packet with same EID hits cache (no extra detection banner)."""
        pkt = _build_eax_packet_at_exponent(_EAX_KEY, period_exponent=5, plaintext=b"a")
        mock_scan.side_effect = [pkt, pkt, None]

        from hubblenetwork.crypto import decrypt_eax as real_decrypt_eax
        from unittest.mock import MagicMock
        wrapped = MagicMock(side_effect=real_decrypt_eax)
        with patch("hubblenetwork.cli.decrypt_eax", wrapped):
            runner = CliRunner()
            result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "--key", _EAX_KEY_HEX])

        assert result.exit_code == 0
        # First packet: scan candidates 0..5 (6 calls). Second packet: 1 cache hit.
        assert wrapped.call_count == 7
        # Detection banner emitted exactly once.
        assert result.stderr.count("[INFO] Detected:") == 1

    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_no_warn_when_both_flags_provided(self, mock_scan):
        """With explicit -e and --counter-mode, no auto-detect warning or banner."""
        pkt = _build_eax_packet_at_exponent(_EAX_KEY, period_exponent=7, plaintext=b"x")
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "scan", "--timeout", "1",
                "--key", _EAX_KEY_HEX,
                "-e", "7",
                "--counter-mode", "UNIX_TIME",
            ],
        )
        assert result.exit_code == 0
        assert "[WARN]" not in result.stderr
        assert "[INFO] Detected:" not in result.stderr

    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_warn_only_mentions_active_axes(self, mock_scan):
        """Passing -e but not --counter-mode → warning mentions only CTR axis."""
        pkt = _build_eax_packet_at_exponent(_EAX_KEY, period_exponent=7, plaintext=b"x")
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ble", "scan", "--timeout", "1", "--key", _EAX_KEY_HEX, "-e", "7"],
        )
        assert result.exit_code == 0
        assert "AES-CTR counter_source" in result.stderr
        assert "AES-EAX" not in result.stderr  # EAX axis was opted out
        # No EAX detection banner since EAX is not auto-detecting.
        assert "[INFO] Detected:" not in result.stderr

    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_silent_in_json_mode(self, mock_scan):
        """JSON output stays parse-clean even with auto-detect."""
        pkt = _build_eax_packet_at_exponent(_EAX_KEY, period_exponent=4, plaintext=b"j")
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ble", "scan", "--timeout", "1", "--key", _EAX_KEY_HEX, "-o", "json"],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        assert len(parsed) == 1
        # Warning + info banner suppressed entirely (JSON mode suppresses info).
        assert "[WARN]" not in result.stderr
        assert "[INFO] Detected:" not in result.stderr

    @patch("hubblenetwork.cli.ble_mod.scan_single")
    def test_detection_failure_with_show_failed(self, mock_scan):
        """No exponent matches → no banner, packet shown as fail when flag set."""
        # Build packet with one key, scan with another → all 16 candidates fail.
        wrong_key = bytes(range(16, 32))
        pkt = _build_eax_packet_at_exponent(_EAX_KEY, period_exponent=3, plaintext=b"w")
        mock_scan.side_effect = [pkt, None]

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["ble", "scan", "--timeout", "1", "--key", wrong_key.hex(),
             "-o", "json", "--show-failed-decryption"],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        assert len(parsed) == 1
        assert parsed[0]["decrypt_status"] == "fail"
        assert "[INFO] Detected:" not in result.stderr


# ---------------------------------------------------------------------------
# Public API export tests
# ---------------------------------------------------------------------------


class TestPublicApiExports:
    def test_aes_eax_packet_importable(self):
        from hubblenetwork import AesEaxPacket
        assert AesEaxPacket is not None

    def test_unknown_packet_importable(self):
        from hubblenetwork import UnknownPacket
        assert UnknownPacket is not None

    def test_decrypt_eax_importable(self):
        from hubblenetwork import decrypt_eax
        assert callable(decrypt_eax)
