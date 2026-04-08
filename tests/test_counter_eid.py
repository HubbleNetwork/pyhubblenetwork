"""Tests for counter-based EID decryption (counter_mode parameter)."""

import struct
import pytest
from click.testing import CliRunner
from Crypto.Cipher import AES

from hubblenetwork.crypto import (
    _get_encryption_key,
    _get_nonce,
    _get_auth_tag,
    decrypt,
)
from hubblenetwork.packets import EncryptedPacket, Location


# ---------------------------------------------------------------------------
# Helpers – build a valid BLE advertisement payload for a given counter value
# ---------------------------------------------------------------------------

def _encrypt_payload(key: bytes, counter_value: int, seq_no: int, plaintext: bytes) -> bytes:
    """Encrypt plaintext the same way firmware does and return a BLE adv payload."""
    keylen = len(key)
    daily_key = _get_encryption_key(key, counter_value, seq_no, keylen=keylen)
    nonce = _get_nonce(key, counter_value, seq_no, keylen=keylen)

    cipher = AES.new(daily_key, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)

    auth_tag = _get_auth_tag(daily_key, ciphertext)

    # BLE adv layout: seq_no (2 big-endian) + 4 padding bytes + auth_tag (4) + ciphertext
    seq_bytes = struct.pack(">H", seq_no & 0x3FF)
    padding = b"\x00" * 4
    return seq_bytes + padding + auth_tag + ciphertext


def _make_encrypted_packet(key: bytes, counter_value: int, seq_no: int, plaintext: bytes) -> EncryptedPacket:
    """Build an EncryptedPacket whose auth_tag matches *counter_value*."""
    payload = _encrypt_payload(key, counter_value, seq_no, plaintext)
    return EncryptedPacket(
        timestamp=1700000000,
        location=Location(lat=0.0, lon=0.0, fake=True),
        payload=payload,
        rssi=-70,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Deterministic 32-byte key (AES-256-CTR)
_KEY_256 = bytes(range(32))
# Deterministic 16-byte key (AES-128-CTR)
_KEY_128 = bytes(range(16))


# ---------------------------------------------------------------------------
# decrypt() with counter_mode
# ---------------------------------------------------------------------------

class TestCounterEidDecrypt:
    """Test decrypt() counter-based EID mode."""

    def test_decrypt_finds_counter_value(self):
        """decrypt() with counter_mode finds the correct counter."""
        counter_value = 7
        pkt = _make_encrypted_packet(_KEY_256, counter_value, seq_no=1, plaintext=b"hello")

        result = decrypt(_KEY_256, pkt, counter_mode=True)

        assert result is not None
        assert result.payload == b"hello"
        assert result.counter == counter_value

    def test_decrypt_counter_zero(self):
        """Counter value 0 is found."""
        pkt = _make_encrypted_packet(_KEY_256, 0, seq_no=5, plaintext=b"zero")

        result = decrypt(_KEY_256, pkt, counter_mode=True)

        assert result is not None
        assert result.counter == 0
        assert result.payload == b"zero"

    def test_decrypt_counter_at_pool_boundary(self):
        """Counter value 127 (last in pool) is found."""
        pkt = _make_encrypted_packet(_KEY_128, 127, seq_no=2, plaintext=b"edge")

        result = decrypt(_KEY_128, pkt, counter_mode=True)

        assert result is not None
        assert result.counter == 127
        assert result.payload == b"edge"

    def test_decrypt_counter_outside_pool_returns_none(self):
        """Counter value >= 128 is not found."""
        pkt = _make_encrypted_packet(_KEY_256, 128, seq_no=3, plaintext=b"miss")

        result = decrypt(_KEY_256, pkt, counter_mode=True)

        assert result is None

    def test_decrypt_wrong_key_returns_none(self):
        """Wrong key doesn't match any counter."""
        pkt = _make_encrypted_packet(_KEY_256, 5, seq_no=1, plaintext=b"data")
        wrong_key = bytes(range(1, 33))

        result = decrypt(wrong_key, pkt, counter_mode=True)

        assert result is None

    def test_decrypt_aes128_counter_mode(self):
        """Counter-based decryption works with AES-128 keys."""
        pkt = _make_encrypted_packet(_KEY_128, 3, seq_no=10, plaintext=b"aes128")

        result = decrypt(_KEY_128, pkt, counter_mode=True)

        assert result is not None
        assert result.payload == b"aes128"
        assert result.counter == 3

    def test_decrypt_preserves_packet_metadata(self):
        """Decrypted packet retains timestamp, rssi, location, sequence."""
        pkt = _make_encrypted_packet(_KEY_256, 2, seq_no=42, plaintext=b"meta")

        result = decrypt(_KEY_256, pkt, counter_mode=True)

        assert result is not None
        assert result.timestamp == 1700000000
        assert result.rssi == -70
        assert result.sequence == 42


# ---------------------------------------------------------------------------
# Validation: counter_mode + days mutual exclusivity
# ---------------------------------------------------------------------------

class TestCounterEidValidation:
    """Test that counter_mode and days are mutually exclusive."""

    def test_raises_when_both_counter_mode_and_days_set(self):
        pkt = _make_encrypted_packet(_KEY_256, 0, seq_no=1, plaintext=b"x")

        with pytest.raises(ValueError, match="Cannot specify both"):
            decrypt(_KEY_256, pkt, days=5, counter_mode=True)

    def test_counter_mode_with_default_days_is_ok(self):
        """counter_mode + days=2 (the default) should NOT raise."""
        pkt = _make_encrypted_packet(_KEY_256, 0, seq_no=1, plaintext=b"ok")

        result = decrypt(_KEY_256, pkt, days=2, counter_mode=True)
        assert result is not None


# ---------------------------------------------------------------------------
# CLI option validation (ble scan / ble detect)
# ---------------------------------------------------------------------------

class TestCliCounterModeOptions:
    """Test --counter-mode CLI option validation."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_scan_counter_mode_without_key_errors(self, runner):
        from hubblenetwork.cli import cli

        result = runner.invoke(cli, ["ble", "scan", "--counter-mode"])
        assert result.exit_code != 0
        assert "requires --key" in result.output or "requires --key" in (result.exception and str(result.exception) or "")

    def test_scan_counter_mode_with_days_errors(self, runner):
        from hubblenetwork.cli import cli

        result = runner.invoke(cli, [
            "ble", "scan",
            "--key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "--counter-mode",
            "--days", "3",
        ])
        assert result.exit_code != 0

    def test_detect_counter_mode_with_days_errors(self, runner):
        from hubblenetwork.cli import cli

        result = runner.invoke(cli, [
            "ble", "detect",
            "--key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "--counter-mode",
            "--days", "3",
        ])
        assert result.exit_code != 0

    def test_scan_help_shows_counter_mode(self, runner):
        from hubblenetwork.cli import cli

        result = runner.invoke(cli, ["ble", "scan", "--help"])
        assert "--counter-mode" in result.output

    def test_detect_help_shows_counter_mode(self, runner):
        from hubblenetwork.cli import cli

        result = runner.invoke(cli, ["ble", "detect", "--help"])
        assert "--counter-mode" in result.output

    def test_detect_help_shows_days(self, runner):
        from hubblenetwork.cli import cli

        result = runner.invoke(cli, ["ble", "detect", "--help"])
        assert "--days" in result.output
