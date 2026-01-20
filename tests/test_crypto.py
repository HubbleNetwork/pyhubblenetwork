"""Tests for crypto.py encryption/decryption functions."""

from __future__ import annotations

import pytest
from unittest.mock import patch
from datetime import datetime, timezone

from hubblenetwork.crypto import (
    ParsedPacket,
    _generate_kdf_key,
    _get_nonce,
    _get_encryption_key,
    _get_auth_tag,
    _aes_decrypt,
    _check_tag_matches,
    decrypt,
    find_time_counter_delta,
)
from hubblenetwork.packets import EncryptedPacket, DecryptedPacket, Location


# Test vectors - these are synthetic values for testing the crypto pipeline
# In real usage, these would come from actual device keys
TEST_KEY_128 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
TEST_KEY_256 = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)


class TestParsedPacket:
    """Tests for ParsedPacket class."""

    def test_parses_sequence_number(self):
        """Test ParsedPacket extracts sequence number from first 2 bytes."""
        # Sequence number is in first 2 bytes, masked with 0x3FF (10 bits)
        # Big-endian: 0x01 0x23 = 291, masked = 291 & 0x3FF = 291
        payload = bytes.fromhex("0123000000aabbccdd1122334455")
        pkt = EncryptedPacket(
            timestamp=1700000000,
            location=None,
            payload=payload,
            rssi=-70,
        )
        parsed = ParsedPacket(pkt)
        assert parsed.seq_no == (0x0123 & 0x3FF)

    def test_parses_auth_tag(self):
        """Test ParsedPacket extracts auth tag from bytes 6-10."""
        payload = bytes.fromhex("000000000000aabbccdd1122334455")
        pkt = EncryptedPacket(
            timestamp=1700000000,
            location=None,
            payload=payload,
            rssi=-70,
        )
        parsed = ParsedPacket(pkt)
        assert parsed.auth_tag == bytes.fromhex("aabbccdd")

    def test_parses_encrypted_payload(self):
        """Test ParsedPacket extracts encrypted payload from byte 10 onwards."""
        payload = bytes.fromhex("000000000000aabbccdd1122334455")
        pkt = EncryptedPacket(
            timestamp=1700000000,
            location=None,
            payload=payload,
            rssi=-70,
        )
        parsed = ParsedPacket(pkt)
        assert parsed.encrypted_payload == bytes.fromhex("1122334455")

    def test_sequence_number_mask(self):
        """Test sequence number is masked to 10 bits."""
        # 0xFFFF masked with 0x3FF = 0x3FF = 1023
        payload = bytes.fromhex("ffff000000aabbccdd1122334455")
        pkt = EncryptedPacket(
            timestamp=1700000000,
            location=None,
            payload=payload,
            rssi=-70,
        )
        parsed = ParsedPacket(pkt)
        assert parsed.seq_no == 0x3FF
        assert parsed.seq_no == 1023


class TestKdfFunctions:
    """Tests for KDF helper functions."""

    def test_generate_kdf_key_128_bit(self):
        """Test KDF key generation with 128-bit output."""
        result = _generate_kdf_key(TEST_KEY_128, 16, "TestLabel", 1)
        assert len(result) == 16
        assert isinstance(result, bytes)

    def test_generate_kdf_key_256_bit(self):
        """Test KDF key generation with 256-bit output."""
        result = _generate_kdf_key(TEST_KEY_256, 32, "TestLabel", 1)
        assert len(result) == 32
        assert isinstance(result, bytes)

    def test_generate_kdf_key_deterministic(self):
        """Test KDF produces same output for same inputs."""
        result1 = _generate_kdf_key(TEST_KEY_128, 16, "TestLabel", 1)
        result2 = _generate_kdf_key(TEST_KEY_128, 16, "TestLabel", 1)
        assert result1 == result2

    def test_generate_kdf_key_different_context(self):
        """Test KDF produces different output for different context."""
        result1 = _generate_kdf_key(TEST_KEY_128, 16, "TestLabel", 1)
        result2 = _generate_kdf_key(TEST_KEY_128, 16, "TestLabel", 2)
        assert result1 != result2

    def test_generate_kdf_key_different_label(self):
        """Test KDF produces different output for different label."""
        result1 = _generate_kdf_key(TEST_KEY_128, 16, "Label1", 1)
        result2 = _generate_kdf_key(TEST_KEY_128, 16, "Label2", 1)
        assert result1 != result2

    def test_get_nonce_correct_size(self):
        """Test nonce generation produces correct size (12 bytes)."""
        nonce = _get_nonce(TEST_KEY_128, time_counter=20000, counter=1, keylen=16)
        assert len(nonce) == 12

    def test_get_nonce_deterministic(self):
        """Test nonce generation is deterministic."""
        nonce1 = _get_nonce(TEST_KEY_128, time_counter=20000, counter=1, keylen=16)
        nonce2 = _get_nonce(TEST_KEY_128, time_counter=20000, counter=1, keylen=16)
        assert nonce1 == nonce2

    def test_get_encryption_key_correct_size(self):
        """Test encryption key generation produces correct size."""
        key = _get_encryption_key(TEST_KEY_128, time_counter=20000, counter=1, keylen=16)
        assert len(key) == 16

        key = _get_encryption_key(TEST_KEY_256, time_counter=20000, counter=1, keylen=32)
        assert len(key) == 32


class TestAuthTag:
    """Tests for auth tag functions."""

    def test_get_auth_tag_size(self):
        """Test auth tag is 4 bytes."""
        tag = _get_auth_tag(TEST_KEY_128, b"test ciphertext")
        assert len(tag) == 4

    def test_get_auth_tag_deterministic(self):
        """Test auth tag is deterministic."""
        tag1 = _get_auth_tag(TEST_KEY_128, b"test ciphertext")
        tag2 = _get_auth_tag(TEST_KEY_128, b"test ciphertext")
        assert tag1 == tag2

    def test_get_auth_tag_different_for_different_data(self):
        """Test auth tag differs for different data."""
        tag1 = _get_auth_tag(TEST_KEY_128, b"data1")
        tag2 = _get_auth_tag(TEST_KEY_128, b"data2")
        assert tag1 != tag2


class TestAesDecrypt:
    """Tests for AES decryption function."""

    def test_aes_decrypt_roundtrip(self):
        """Test AES encrypt/decrypt roundtrip."""
        from Crypto.Cipher import AES

        key = TEST_KEY_128
        nonce = b"\x00" * 12
        plaintext = b"Hello, World!"

        # Encrypt
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        # Decrypt with our function
        decrypted = _aes_decrypt(key, nonce, ciphertext)
        assert decrypted == plaintext


class TestDecrypt:
    """Tests for main decrypt function."""

    def _create_valid_packet(self, key: bytes, time_counter: int, seq_no: int) -> EncryptedPacket:
        """Helper to create a validly encrypted packet for testing."""
        from Crypto.Cipher import AES

        keylen = len(key)
        plaintext = b"Test payload!"

        # Get the encryption key and nonce that would be used
        daily_key = _get_encryption_key(key, time_counter, seq_no, keylen)
        nonce = _get_nonce(key, time_counter, seq_no, keylen)

        # Encrypt the payload
        cipher = AES.new(daily_key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        # Generate auth tag
        auth_tag = _get_auth_tag(daily_key, ciphertext)

        # Build the BLE advertisement payload format:
        # bytes 0-1: sequence number (big-endian, only lower 10 bits used)
        # bytes 2-5: padding/reserved
        # bytes 6-9: auth tag
        # bytes 10+: encrypted payload
        seq_bytes = seq_no.to_bytes(2, "big")
        padding = b"\x00" * 4
        payload = seq_bytes + padding + auth_tag + ciphertext

        return EncryptedPacket(
            timestamp=1700000000,
            location=Location(lat=90.0, lon=0.0, fake=True),
            payload=payload,
            rssi=-70,
        )

    def test_decrypt_with_correct_key_today(self):
        """Test decrypt succeeds with correct key and today's time counter."""
        # Mock datetime to have a predictable time_counter
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            pkt = self._create_valid_packet(TEST_KEY_256, time_counter, seq_no=42)
            result = decrypt(TEST_KEY_256, pkt)

            assert result is not None
            assert isinstance(result, DecryptedPacket)
            assert result.payload == b"Test payload!"
            assert result.sequence == 42
            assert result.counter == time_counter

    def test_decrypt_with_wrong_key_returns_none(self):
        """Test decrypt returns None with wrong key."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            pkt = self._create_valid_packet(TEST_KEY_256, time_counter, seq_no=42)

            # Try to decrypt with different key
            wrong_key = bytes.fromhex(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
            result = decrypt(wrong_key, pkt)

            assert result is None

    def test_decrypt_with_corrupted_packet_returns_none(self):
        """Test decrypt returns None with corrupted packet."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            pkt = self._create_valid_packet(TEST_KEY_256, time_counter, seq_no=42)

            # Corrupt the auth tag
            corrupted_payload = bytearray(pkt.payload)
            corrupted_payload[6] ^= 0xFF
            corrupted_pkt = EncryptedPacket(
                timestamp=pkt.timestamp,
                location=pkt.location,
                payload=bytes(corrupted_payload),
                rssi=pkt.rssi,
            )

            result = decrypt(TEST_KEY_256, corrupted_pkt)
            assert result is None

    def test_decrypt_with_past_day(self):
        """Test decrypt finds packet from past day within range."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            # Create packet with yesterday's time counter
            pkt = self._create_valid_packet(TEST_KEY_256, time_counter - 1, seq_no=42)
            result = decrypt(TEST_KEY_256, pkt, days=2)

            assert result is not None
            assert result.counter == time_counter - 1

    def test_decrypt_preserves_packet_metadata(self):
        """Test decrypt preserves timestamp, location, rssi from original packet."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            pkt = self._create_valid_packet(TEST_KEY_256, time_counter, seq_no=42)
            result = decrypt(TEST_KEY_256, pkt)

            assert result is not None
            assert result.timestamp == 1700000000
            assert result.rssi == -70
            assert result.location.fake is True


class TestFindTimeCounterDelta:
    """Tests for find_time_counter_delta function."""

    def _create_valid_packet(self, key: bytes, time_counter: int, seq_no: int) -> EncryptedPacket:
        """Helper to create a validly encrypted packet for testing."""
        from Crypto.Cipher import AES

        keylen = len(key)
        plaintext = b"Test payload!"

        daily_key = _get_encryption_key(key, time_counter, seq_no, keylen)
        nonce = _get_nonce(key, time_counter, seq_no, keylen)

        cipher = AES.new(daily_key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)

        auth_tag = _get_auth_tag(daily_key, ciphertext)

        seq_bytes = seq_no.to_bytes(2, "big")
        padding = b"\x00" * 4
        payload = seq_bytes + padding + auth_tag + ciphertext

        return EncryptedPacket(
            timestamp=1700000000,
            location=Location(lat=90.0, lon=0.0, fake=True),
            payload=payload,
            rssi=-70,
        )

    def test_delta_zero_for_today(self):
        """Test delta is 0 when packet is from today."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            pkt = self._create_valid_packet(TEST_KEY_256, time_counter, seq_no=42)
            delta = find_time_counter_delta(TEST_KEY_256, pkt)

            assert delta == 0

    def test_negative_delta_for_past(self):
        """Test negative delta when packet is from past days."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            # Create packet from 5 days ago
            pkt = self._create_valid_packet(TEST_KEY_256, time_counter - 5, seq_no=42)
            delta = find_time_counter_delta(TEST_KEY_256, pkt, max_days_back=10)

            assert delta == -5

    def test_positive_delta_for_future(self):
        """Test positive delta when packet is from future days."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            # Create packet from 2 days ahead
            pkt = self._create_valid_packet(TEST_KEY_256, time_counter + 2, seq_no=42)
            delta = find_time_counter_delta(TEST_KEY_256, pkt)

            assert delta == 2

    def test_none_for_wrong_key(self):
        """Test returns None when key doesn't match."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
        time_counter = int(fixed_time.timestamp()) // 86400

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            pkt = self._create_valid_packet(TEST_KEY_256, time_counter, seq_no=42)

            wrong_key = bytes.fromhex(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
            delta = find_time_counter_delta(wrong_key, pkt, max_days_back=5)

            assert delta is None

    def test_finds_epoch_time_counter(self):
        """Test finds packet with time counter near epoch (0-365)."""
        fixed_time = datetime(2023, 11, 14, 12, 0, 0, tzinfo=timezone.utc)

        with patch("hubblenetwork.crypto.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            mock_dt.timezone = timezone

            # Create packet with absolute time counter = 10 (10 days from epoch)
            pkt = self._create_valid_packet(TEST_KEY_256, 10, seq_no=42)
            delta = find_time_counter_delta(TEST_KEY_256, pkt)

            # Delta should be 10 - today's time_counter (large negative number)
            current_tc = int(fixed_time.timestamp()) // 86400
            assert delta == 10 - current_tc
