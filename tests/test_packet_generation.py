"""Tests for packet generation (encrypt / encrypt_eax)."""

from hubblenetwork.crypto import _generate_ctr_eid


class TestGenerateCtrEid:
    def test_returns_4_bytes(self):
        key = bytes(range(32))
        eid = _generate_ctr_eid(key, time_counter=12345, keylen=32)
        assert isinstance(eid, bytes)
        assert len(eid) == 4

    def test_deterministic(self):
        key = bytes(range(32))
        a = _generate_ctr_eid(key, time_counter=12345, keylen=32)
        b = _generate_ctr_eid(key, time_counter=12345, keylen=32)
        assert a == b

    def test_changes_with_time_counter(self):
        key = bytes(range(32))
        a = _generate_ctr_eid(key, time_counter=12345, keylen=32)
        b = _generate_ctr_eid(key, time_counter=12346, keylen=32)
        assert a != b

    def test_aes_128_key(self):
        key = bytes(range(16))
        eid = _generate_ctr_eid(key, time_counter=0, keylen=16)
        assert len(eid) == 4


import pytest
from hubblenetwork.crypto import (
    encrypt,
    decrypt,
    UNIX_TIME,
    DEVICE_UPTIME,
    MAX_CTR_PAYLOAD,
)


class TestEncryptCtr:
    def test_round_trip_aes_256(self):
        key = bytes(range(32))
        plaintext = b"hello world"
        pkt = encrypt(key, plaintext, time_counter=7, seq_no=42, counter_mode=DEVICE_UPTIME)
        result = decrypt(key, pkt, counter_mode=DEVICE_UPTIME)
        assert result is not None
        assert result.payload == plaintext
        assert result.counter == 7
        assert result.sequence == 42

    def test_round_trip_aes_128(self):
        key = bytes(range(16))
        plaintext = b"hi"
        pkt = encrypt(key, plaintext, time_counter=3, seq_no=100, counter_mode=DEVICE_UPTIME)
        result = decrypt(key, pkt, counter_mode=DEVICE_UPTIME)
        assert result is not None
        assert result.payload == plaintext
        assert result.counter == 3
        assert result.sequence == 100

    def test_unix_time_default(self):
        """Without time_counter, defaults to today's UTC day; decrypt() default mode finds it."""
        key = bytes(range(32))
        pkt = encrypt(key, b"x", seq_no=1)
        result = decrypt(key, pkt)  # default UNIX_TIME, ±2 days
        assert result is not None
        assert result.payload == b"x"
        assert result.sequence == 1

    def test_random_seq_no_when_omitted(self):
        """Without seq_no, two calls produce different bytes."""
        key = bytes(range(32))
        a = encrypt(key, b"x", time_counter=5, counter_mode=DEVICE_UPTIME)
        b = encrypt(key, b"x", time_counter=5, counter_mode=DEVICE_UPTIME)
        assert a.payload != b.payload

    def test_deterministic_with_explicit_inputs(self):
        key = bytes(range(32))
        a = encrypt(key, b"x", time_counter=5, seq_no=7, counter_mode=DEVICE_UPTIME)
        b = encrypt(key, b"x", time_counter=5, seq_no=7, counter_mode=DEVICE_UPTIME)
        assert a.payload == b.payload

    def test_eid_matches_helper(self):
        key = bytes(range(32))
        pkt = encrypt(key, b"x", time_counter=5, seq_no=7, counter_mode=DEVICE_UPTIME)
        # Service data layout: header(2) | EID(4) | auth_tag(4) | ciphertext
        eid_bytes = pkt.payload[2:6]
        assert eid_bytes == _generate_ctr_eid(key, 5, keylen=32)

    def test_protocol_version_zero(self):
        key = bytes(range(32))
        pkt = encrypt(key, b"x", time_counter=5, seq_no=7, counter_mode=DEVICE_UPTIME)
        # Top 6 bits of byte 0 are version (0 for AES-CTR)
        assert (pkt.payload[0] >> 2) == 0
        assert pkt.protocol_version == 0

    def test_seq_no_encoded_in_header(self):
        key = bytes(range(32))
        pkt = encrypt(key, b"x", time_counter=5, seq_no=0x123, counter_mode=DEVICE_UPTIME)
        seq_extracted = int.from_bytes(pkt.payload[0:2], "big") & 0x3FF
        assert seq_extracted == 0x123


import struct
from hubblenetwork.crypto import encrypt_eax, decrypt_eax
from hubblenetwork import ble as ble_mod
from hubblenetwork.packets import AesEaxPacket


class TestEncryptEax:
    KEY_128 = bytes(range(16))

    def test_round_trip_default(self):
        plaintext = b"abc"
        pkt = encrypt_eax(self.KEY_128, plaintext)
        # Re-parse the service data bytes back into an AesEaxPacket
        parsed = ble_mod._make_packet(pkt.payload, rssi=0)
        assert isinstance(parsed, AesEaxPacket)
        result = decrypt_eax(self.KEY_128, parsed)
        assert result is not None
        assert result.payload == plaintext

    def test_round_trip_with_explicit_inputs(self):
        plaintext = b"abcdefghi"  # 9 bytes, max
        nonce_salt = b"\xa3\xf1"
        pkt = encrypt_eax(
            self.KEY_128, plaintext,
            counter=3, nonce_salt=nonce_salt, period_exponent=0,
        )
        parsed = ble_mod._make_packet(pkt.payload, rssi=0)
        assert isinstance(parsed, AesEaxPacket)
        assert parsed.nonce_salt == nonce_salt
        result = decrypt_eax(self.KEY_128, parsed, period_exponent=0)
        assert result is not None
        assert result.payload == plaintext

    def test_round_trip_with_period_exponent(self):
        plaintext = b"x"
        pkt = encrypt_eax(
            self.KEY_128, plaintext,
            counter=2, nonce_salt=b"\x00\x01", period_exponent=3,
        )
        parsed = ble_mod._make_packet(pkt.payload, rssi=0)
        result = decrypt_eax(self.KEY_128, parsed, period_exponent=3)
        assert result is not None
        assert result.payload == plaintext

    def test_random_nonce_salt_when_omitted(self):
        a = encrypt_eax(self.KEY_128, b"x")
        b = encrypt_eax(self.KEY_128, b"x")
        assert a.payload != b.payload

    def test_deterministic_with_explicit_inputs(self):
        a = encrypt_eax(self.KEY_128, b"x", counter=0, nonce_salt=b"\x00\x00")
        b = encrypt_eax(self.KEY_128, b"x", counter=0, nonce_salt=b"\x00\x00")
        assert a.payload == b.payload

    def test_protocol_version_two(self):
        pkt = encrypt_eax(self.KEY_128, b"x", counter=0, nonce_salt=b"\x00\x00")
        # Top 6 bits of byte 0 = version (2 for AES-EAX) → 0x08
        assert (pkt.payload[0] >> 2) == 2
        assert pkt.protocol_version == 2

    def test_eid_embedded_little_endian(self):
        pkt = encrypt_eax(self.KEY_128, b"", counter=0, nonce_salt=b"\x00\x00")
        # offset 3-11 is the 8-byte EID, little-endian
        embedded_eid = struct.unpack("<Q", pkt.payload[3:11])[0]
        assert pkt.eid == embedded_eid

    def test_returns_encrypted_packet(self):
        """encrypt_eax returns EncryptedPacket so it flows through ingest unchanged."""
        from hubblenetwork.packets import EncryptedPacket as Pkt
        pkt = encrypt_eax(self.KEY_128, b"x")
        assert isinstance(pkt, Pkt)


class TestValidation:
    def test_ctr_invalid_key_length(self):
        with pytest.raises(ValueError, match="16 or 32"):
            encrypt(bytes(20), b"x")

    def test_ctr_payload_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            encrypt(bytes(32), b"x" * 14)

    def test_ctr_seq_no_out_of_range_high(self):
        with pytest.raises(ValueError, match="0..1023"):
            encrypt(bytes(32), b"x", seq_no=1024)

    def test_ctr_seq_no_out_of_range_negative(self):
        with pytest.raises(ValueError, match="0..1023"):
            encrypt(bytes(32), b"x", seq_no=-1)

    def test_ctr_invalid_counter_mode(self):
        with pytest.raises(ValueError, match="counter_mode"):
            encrypt(bytes(32), b"x", counter_mode="GARBAGE")

    def test_eax_invalid_key_length(self):
        with pytest.raises(ValueError, match="16-byte"):
            encrypt_eax(bytes(32), b"x")

    def test_eax_payload_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            encrypt_eax(bytes(16), b"x" * 10)

    def test_eax_nonce_salt_wrong_size(self):
        with pytest.raises(ValueError, match="2 bytes"):
            encrypt_eax(bytes(16), b"x", nonce_salt=b"\x00")

    def test_eax_period_exponent_too_high(self):
        with pytest.raises(ValueError, match="0..15"):
            encrypt_eax(bytes(16), b"x", period_exponent=16)

    def test_eax_period_exponent_negative(self):
        with pytest.raises(ValueError, match="0..15"):
            encrypt_eax(bytes(16), b"x", period_exponent=-1)


class TestEaxHighCounterRegression:
    """Defense-in-depth: regression test for the regime where the inlined EID
    formula and the existing `_generate_eid` helper would diverge.

    With period_exponent=15 and counter=127, effective_counter = 127 * 32768 =
    4,161,536, which is well above the 65,536 boundary at which
    `_derive_eid_key` starts producing different key_0 depending on whether
    `counter` or `0` is passed in. Round-tripping at that regime catches
    accidental reintroduction of `_generate_eid` here.
    """

    def test_high_counter_round_trip(self):
        key = bytes(range(16))
        plaintext = b"hi"
        pkt = encrypt_eax(
            key, plaintext,
            counter=127, nonce_salt=b"\xab\xcd", period_exponent=15,
        )
        parsed = ble_mod._make_packet(pkt.payload, rssi=0)
        assert isinstance(parsed, AesEaxPacket)
        result = decrypt_eax(key, parsed, period_exponent=15)
        assert result is not None
        assert result.payload == plaintext


class TestPublicExports:
    def test_encrypt_importable_from_root(self):
        from hubblenetwork import encrypt as e
        assert callable(e)

    def test_encrypt_eax_importable_from_root(self):
        from hubblenetwork import encrypt_eax as e
        assert callable(e)
