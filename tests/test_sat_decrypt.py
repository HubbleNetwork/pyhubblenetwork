"""Tests for satellite packet decryption (`decrypt_satellite` and `sat scan --key`)."""

from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Protocol.KDF import SP800_108_Counter

from hubblenetwork import DEVICE_UPTIME, UNIX_TIME, decrypt_satellite
from hubblenetwork.crypto import decrypt_satellite_with_offset
from hubblenetwork.cli import cli
from hubblenetwork.errors import DockerError
from hubblenetwork.packets import SatellitePacket
from hubblenetwork import sat


# ---------------------------------------------------------------------------
# Reference encryption helpers (mirrors firmware / platform-e2e-tests)
# ---------------------------------------------------------------------------


def _kdf(key: bytes, size: int, label: str, context) -> bytes:
    return SP800_108_Counter(
        key,
        size,
        lambda k, d: CMAC.new(k, d, AES).digest(),
        label=label.encode(),
        context=str(context).encode(),
    )


def _enc_key(master: bytes, time_counter: int, counter: int) -> bytes:
    ek = _kdf(master, len(master), "EncryptionKey", time_counter)
    return _kdf(ek, len(master), "Key", counter)


def _nonce(master: bytes, time_counter: int, counter: int) -> bytes:
    nk = _kdf(master, len(master), "NonceKey", time_counter)
    return _kdf(nk, 12, "Nonce", counter)


def make_encrypted_sat_payload(
    master_key: bytes,
    seq_no: int,
    plaintext: bytes,
    time_counter: int,
) -> tuple[bytes, bytes]:
    """Return (encrypted_payload, auth_tag) for a satellite packet.

    Matches the BLE-equivalent AES-CTR + CMAC scheme used by Hubble firmware.
    """
    enc_key = _enc_key(master_key, time_counter, seq_no)
    nonce = _nonce(master_key, time_counter, seq_no)
    ciphertext = AES.new(enc_key, AES.MODE_CTR, nonce=nonce).encrypt(plaintext)
    auth_tag = CMAC.new(enc_key, ciphertext, AES).digest()[:4]
    return ciphertext, auth_tag


_MASTER_256 = bytes(range(32))
_MASTER_128 = bytes(range(16))
_TODAY_TC = int(datetime.now(timezone.utc).timestamp()) // 86400


# ---------------------------------------------------------------------------
# decrypt_satellite
# ---------------------------------------------------------------------------


class TestDecryptSatellite:
    def test_roundtrip_aes256_today(self):
        plaintext = b"hello sat"
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 5, plaintext, _TODAY_TC)
        out = decrypt_satellite(
            _MASTER_256, seq_no=5, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400,
        )
        assert out == plaintext

    def test_roundtrip_aes128(self):
        plaintext = b"abc123"
        ct, tag = make_encrypted_sat_payload(_MASTER_128, 17, plaintext, _TODAY_TC)
        out = decrypt_satellite(
            _MASTER_128, seq_no=17, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400,
        )
        assert out == plaintext

    def test_finds_neighbouring_day(self):
        # Packet was encrypted for yesterday but received "today".
        plaintext = b"yesterday"
        enc_tc = _TODAY_TC - 1
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 9, plaintext, enc_tc)
        out = decrypt_satellite(
            _MASTER_256, seq_no=9, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400, days=2,
        )
        assert out == plaintext

    def test_wrong_key_returns_none(self):
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 1, b"secret", _TODAY_TC)
        wrong = bytes([0xFF] * 32)
        out = decrypt_satellite(
            wrong, seq_no=1, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400,
        )
        assert out is None

    def test_out_of_window_returns_none(self):
        plaintext = b"old"
        enc_tc = _TODAY_TC - 10
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 3, plaintext, enc_tc)
        out = decrypt_satellite(
            _MASTER_256, seq_no=3, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400, days=2,
        )
        assert out is None

    def test_timestamp_none_uses_today(self):
        plaintext = b"now"
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 7, plaintext, _TODAY_TC)
        out = decrypt_satellite(
            _MASTER_256, seq_no=7, auth_tag=tag, encrypted_payload=ct,
        )
        assert out == plaintext

    def test_device_uptime_roundtrip(self):
        # Device-uptime packets encode the counter (0-127) as time_counter.
        plaintext = b"uptime!"
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 11, plaintext, 5)
        out = decrypt_satellite(
            _MASTER_256, seq_no=11, auth_tag=tag, encrypted_payload=ct,
            counter_mode=DEVICE_UPTIME,
        )
        assert out == plaintext

    def test_device_uptime_aes128(self):
        plaintext = b"u128"
        ct, tag = make_encrypted_sat_payload(_MASTER_128, 3, plaintext, 120)
        out = decrypt_satellite(
            _MASTER_128, seq_no=3, auth_tag=tag, encrypted_payload=ct,
            counter_mode=DEVICE_UPTIME,
        )
        assert out == plaintext

    def test_device_uptime_out_of_pool_returns_none(self):
        # Counter 200 is outside the fixed 0-127 pool.
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 1, b"far", 200)
        out = decrypt_satellite(
            _MASTER_256, seq_no=1, auth_tag=tag, encrypted_payload=ct,
            counter_mode=DEVICE_UPTIME,
        )
        assert out is None

    def test_unix_time_does_not_match_uptime_packet(self):
        # A device-uptime packet (small counter) must not resolve under UNIX_TIME.
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 4, b"nope", 5)
        out = decrypt_satellite(
            _MASTER_256, seq_no=4, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400, counter_mode=UNIX_TIME,
        )
        assert out is None

    def test_invalid_counter_mode_raises(self):
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 1, b"x", _TODAY_TC)
        with pytest.raises(ValueError):
            decrypt_satellite(
                _MASTER_256, seq_no=1, auth_tag=tag, encrypted_payload=ct,
                counter_mode="BOGUS",
            )

    def test_device_uptime_with_days_raises(self):
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 1, b"x", 5)
        with pytest.raises(ValueError):
            decrypt_satellite(
                _MASTER_256, seq_no=1, auth_tag=tag, encrypted_payload=ct,
                counter_mode=DEVICE_UPTIME, days=5,
            )


class TestDecryptSatelliteWithOffset:
    def test_same_day_offset_zero(self):
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 5, b"today", _TODAY_TC)
        out = decrypt_satellite_with_offset(
            _MASTER_256, seq_no=5, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400,
        )
        assert out == (b"today", 0)

    def test_previous_day_offset_negative(self):
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 9, b"yday", _TODAY_TC - 1)
        out = decrypt_satellite_with_offset(
            _MASTER_256, seq_no=9, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400, days=2,
        )
        assert out == (b"yday", -1)

    def test_next_day_offset_positive(self):
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 9, b"tmrw", _TODAY_TC + 1)
        out = decrypt_satellite_with_offset(
            _MASTER_256, seq_no=9, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400, days=2,
        )
        assert out == (b"tmrw", 1)

    def test_device_uptime_offset_is_none(self):
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 11, b"up", 5)
        out = decrypt_satellite_with_offset(
            _MASTER_256, seq_no=11, auth_tag=tag, encrypted_payload=ct,
            counter_mode=DEVICE_UPTIME,
        )
        assert out == (b"up", None)

    def test_no_match_returns_none(self):
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 1, b"secret", _TODAY_TC)
        out = decrypt_satellite_with_offset(
            bytes([0xFF] * 32), seq_no=1, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400,
        )
        assert out is None

    def test_decrypt_satellite_delegates(self):
        # The plain wrapper still returns just the payload bytes.
        ct, tag = make_encrypted_sat_payload(_MASTER_256, 5, b"plain", _TODAY_TC)
        assert decrypt_satellite(
            _MASTER_256, seq_no=5, auth_tag=tag, encrypted_payload=ct,
            timestamp=_TODAY_TC * 86400,
        ) == b"plain"


# ---------------------------------------------------------------------------
# JSONL parsing of auth_tag
# ---------------------------------------------------------------------------


class TestAuthTagParsing:
    def test_auth_tag_parsed_to_bytes(self):
        payload_b64 = base64.b64encode(b"\x01\x02\x03").decode()
        line = (
            '{"device_id": "0xAA", "seq_num": 1, "device_type": "silabs", '
            '"timestamp": 0.0, "rssi_dB": 0.0, "channel_num": 0, '
            f'"freq_offset_hz": 0.0, "auth_tag": 305419896, "payload_b64": "{payload_b64}"}}\n'
        )
        pkts = sat._parse_jsonl(line)
        assert len(pkts) == 1
        assert pkts[0].auth_tag == (305419896).to_bytes(4, "big")

    def test_missing_auth_tag_is_none(self):
        payload_b64 = base64.b64encode(b"\x01").decode()
        line = (
            '{"device_id": "0xAA", "seq_num": 1, "device_type": "silabs", '
            '"timestamp": 0.0, "rssi_dB": 0.0, "channel_num": 0, '
            f'"freq_offset_hz": 0.0, "payload_b64": "{payload_b64}"}}\n'
        )
        pkts = sat._parse_jsonl(line)
        assert len(pkts) == 1
        assert pkts[0].auth_tag is None


# ---------------------------------------------------------------------------
# CLI - sat scan --key
# ---------------------------------------------------------------------------


def _make_encrypted_sat_pkt(
    seq_no=42, plaintext=b"data_42", time_counter=_TODAY_TC, master=_MASTER_256
) -> SatellitePacket:
    ct, tag = make_encrypted_sat_payload(master, seq_no, plaintext, time_counter)
    return SatellitePacket(
        device_id="0xBB2973BD",
        seq_num=seq_no,
        device_type="silabs",
        timestamp=_TODAY_TC * 86400 + 100,
        rssi_dB=-42.3,
        channel_num=2,
        freq_offset_hz=21654.5,
        payload=ct,
        auth_tag=tag,
    )


class TestSatScanKeyCli:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_key_option_in_help(self, runner):
        result = runner.invoke(cli, ["sat", "scan", "--help"])
        assert result.exit_code == 0
        assert "--key" in result.output

    def test_decrypts_payload_tabular(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt()
        monkeypatch.setattr(sat, "DockerError", DockerError, raising=False)

        import hubblenetwork.cli as cli_mod

        monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter([pkt]))
        monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)

        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--timeout", "1",
             "--poll-interval", "0.1", "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "data_42" in result.output

    def test_hides_undecryptable_by_default(self, runner, monkeypatch):
        # Packet that the key cannot decrypt (random ciphertext + bogus tag).
        bad = SatellitePacket(
            device_id="0xBB2973BD", seq_num=1, device_type="silabs",
            timestamp=_TODAY_TC * 86400, rssi_dB=-42.3, channel_num=2,
            freq_offset_hz=21654.5, payload=b"\xde\xad\xbe\xef",
            auth_tag=b"\x00\x00\x00\x00",
        )
        import hubblenetwork.cli as cli_mod

        monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter([bad]))
        monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)

        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--timeout", "1",
             "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "0 packet(s) received" in result.output

    def test_show_failed_decryption(self, runner, monkeypatch):
        bad = SatellitePacket(
            device_id="0xBB2973BD", seq_num=1, device_type="silabs",
            timestamp=_TODAY_TC * 86400, rssi_dB=-42.3, channel_num=2,
            freq_offset_hz=21654.5, payload=b"\xde\xad\xbe\xef",
            auth_tag=b"\x00\x00\x00\x00",
        )
        import hubblenetwork.cli as cli_mod

        monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter([bad]))
        monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)

        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(),
             "--show-failed-decryption", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "FAIL" in result.output
        assert "1 packet(s) received" in result.output

    def test_decrypts_payload_json(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(seq_no=42, plaintext=b"hello")
        import hubblenetwork.cli as cli_mod

        monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter([pkt]))
        monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)

        result = runner.invoke(
            cli,
            ["sat", "scan", "-o", "json", "--key", _MASTER_256.hex(),
             "--show-failed-decryption", "--payload-format", "string",
             "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "hello" in result.output
        assert '"decrypt_status": "ok"' in result.output

    def test_decrypts_payload_json_no_status_without_flag(self, runner, monkeypatch):
        # Without --show-failed-decryption, no decrypt_status field (matches BLE).
        pkt = _make_encrypted_sat_pkt(seq_no=42, plaintext=b"hello")
        import hubblenetwork.cli as cli_mod

        monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter([pkt]))
        monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)

        result = runner.invoke(
            cli,
            ["sat", "scan", "-o", "json", "--key", _MASTER_256.hex(),
             "--payload-format", "string", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "hello" in result.output
        assert "decrypt_status" not in result.output

    def test_autodetect_device_uptime(self, runner, monkeypatch):
        # No --counter-mode: a device-uptime packet should auto-detect and decrypt.
        pkt = _make_encrypted_sat_pkt(seq_no=42, plaintext=b"up_data", time_counter=5)
        import hubblenetwork.cli as cli_mod

        monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter([pkt]))
        monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)

        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--timeout", "1",
             "--poll-interval", "0.1", "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "up_data" in result.output
        assert "Detected: AES-256-CTR, counter_source=DEVICE_UPTIME" in result.output

    def test_autodetect_unix_time_announced(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(seq_no=42, plaintext=b"day_data")
        import hubblenetwork.cli as cli_mod

        monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter([pkt]))
        monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)

        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--timeout", "1",
             "--poll-interval", "0.1", "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "day_data" in result.output
        assert "Detected: AES-256-CTR, counter_source=UNIX_TIME" in result.output

    def test_explicit_counter_mode_device_uptime(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(seq_no=42, plaintext=b"up_data", time_counter=5)
        import hubblenetwork.cli as cli_mod

        monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter([pkt]))
        monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)

        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--counter-mode",
             "DEVICE_UPTIME", "--timeout", "1", "--poll-interval", "0.1",
             "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "up_data" in result.output
        # Explicit mode skips auto-detect, so no "Detected:" line.
        assert "Detected:" not in result.output

    def test_device_uptime_requires_key(self, runner):
        result = runner.invoke(
            cli, ["sat", "scan", "--counter-mode", "DEVICE_UPTIME", "--timeout", "1"]
        )
        assert result.exit_code != 0
        assert "DEVICE_UPTIME requires --key" in result.output

    def test_device_uptime_days_mutually_exclusive(self, runner):
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--counter-mode",
             "DEVICE_UPTIME", "--days", "3", "--timeout", "1"],
        )
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output

    def test_counter_mode_in_help(self, runner):
        result = runner.invoke(cli, ["sat", "scan", "--help"])
        assert result.exit_code == 0
        assert "--counter-mode" in result.output


# ---------------------------------------------------------------------------
# CLI - sat scan with multiple comma-separated keys
# ---------------------------------------------------------------------------

# Distinct keys so their 8-hex-char prefixes differ (range-based keys collide).
_KEY_A = bytes([0xAA] * 32)
_KEY_B = bytes([0xBB] * 32)
_PREFIX_A = "aaaaaaaa"
_PREFIX_B = "bbbbbbbb"


def _patch_scan(monkeypatch, *pkts):
    import hubblenetwork.cli as cli_mod

    monkeypatch.setattr(cli_mod.sat_mod, "scan", lambda **kw: iter(pkts))
    monkeypatch.setattr(cli_mod.sat_mod, "ensure_docker_available", lambda: None)


class TestSatScanMultipleKeysCli:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_multiple_keys_add_key_column(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"hi", master=_KEY_B)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", f"{_KEY_A.hex()},{_KEY_B.hex()}",
             "--timeout", "1", "--poll-interval", "0.1",
             "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "KEY" in result.output  # column header present
        assert "hi" in result.output

    def test_single_key_no_key_column(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"hi", master=_KEY_A)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _KEY_A.hex(), "--timeout", "1",
             "--poll-interval", "0.1", "--payload-format", "string"],
        )
        assert result.exit_code == 0
        # No KEY column header in the table for a single key.
        assert "| KEY" not in result.output

    def test_first_matching_key_wins(self, runner, monkeypatch):
        # Packet encrypted with the second key; KEY column shows that key.
        pkt = _make_encrypted_sat_pkt(plaintext=b"second", master=_KEY_B)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", f"{_KEY_A.hex()},{_KEY_B.hex()}",
             "--timeout", "1", "--poll-interval", "0.1",
             "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "second" in result.output
        assert _PREFIX_B in result.output

    def test_key_order_independent_match(self, runner, monkeypatch):
        # Packet encrypted with KEY_A but KEY_B is listed first.
        pkt = _make_encrypted_sat_pkt(plaintext=b"first", master=_KEY_A)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", f"{_KEY_B.hex()},{_KEY_A.hex()}",
             "--timeout", "1", "--poll-interval", "0.1",
             "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "first" in result.output
        assert _PREFIX_A in result.output

    def test_failed_decryption_key_column_dash(self, runner, monkeypatch):
        bad = SatellitePacket(
            device_id="0xCAFE", seq_num=1, device_type="silabs",
            timestamp=_TODAY_TC * 86400, rssi_dB=-1.0, channel_num=1,
            freq_offset_hz=0.0, payload=b"\xde\xad\xbe\xef",
            auth_tag=b"\x00\x00\x00\x00",
        )
        _patch_scan(monkeypatch, bad)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", f"{_KEY_A.hex()},{_KEY_B.hex()}",
             "--show-failed-decryption", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "FAIL" in result.output
        # No key matched: neither prefix appears (KEY column shows "-").
        assert _PREFIX_A not in result.output
        assert _PREFIX_B not in result.output

    def test_json_includes_matching_key_full_hex(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"json", master=_KEY_B)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "-o", "json", "--key",
             f"{_KEY_A.hex()},{_KEY_B.hex()}", "--payload-format", "string",
             "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert f'"key": "{_KEY_B.hex()}"' in result.output

    def test_json_single_key_no_key_field(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"json", master=_KEY_A)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "-o", "json", "--key", _KEY_A.hex(),
             "--payload-format", "string", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert '"key"' not in result.output

    def test_invalid_key_in_list_names_it(self, runner, monkeypatch):
        _patch_scan(monkeypatch)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", f"{_KEY_A.hex()},!!!!", "--timeout", "1",
             "--poll-interval", "0.1"],
        )
        assert result.exit_code != 0
        assert "Invalid key" in result.output
        assert "!!!!" in result.output

    def test_whitespace_and_empty_entries_ignored(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"ws", master=_KEY_B)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", f" {_KEY_A.hex()} , , {_KEY_B.hex()} ",
             "--timeout", "1", "--poll-interval", "0.1",
             "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "ws" in result.output
        assert _PREFIX_B in result.output

    def test_base64_key_displayed_as_base64_in_table(self, runner, monkeypatch):
        # A base64-supplied key must render as base64 in the KEY column, not as
        # re-encoded hex.
        key_a_b64 = base64.b64encode(_KEY_A).decode()
        key_b_b64 = base64.b64encode(_KEY_B).decode()
        pkt = _make_encrypted_sat_pkt(plaintext=b"b64", master=_KEY_B)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", f"{key_a_b64},{key_b_b64}",
             "--timeout", "1", "--poll-interval", "0.1",
             "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "b64" in result.output
        assert key_b_b64[:8] in result.output  # base64 prefix shown
        assert _PREFIX_B not in result.output  # not the hex prefix

    def test_base64_key_in_json_is_base64(self, runner, monkeypatch):
        key_a_b64 = base64.b64encode(_KEY_A).decode()
        key_b_b64 = base64.b64encode(_KEY_B).decode()
        pkt = _make_encrypted_sat_pkt(plaintext=b"b64", master=_KEY_B)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "-o", "json", "--key", f"{key_a_b64},{key_b_b64}",
             "--payload-format", "string", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert f'"key": "{key_b_b64}"' in result.output

    def test_per_key_counter_mode_autodetected_independently(self, runner, monkeypatch):
        # KEY_A packet rotates on UNIX_TIME, KEY_B packet on DEVICE_UPTIME.
        # Each key's counter source must be detected and announced separately.
        pkt_a = _make_encrypted_sat_pkt(
            seq_no=1, plaintext=b"unix_a", time_counter=_TODAY_TC, master=_KEY_A
        )
        pkt_b = _make_encrypted_sat_pkt(
            seq_no=2, plaintext=b"uptime_b", time_counter=5, master=_KEY_B
        )
        _patch_scan(monkeypatch, pkt_a, pkt_b)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", f"{_KEY_A.hex()},{_KEY_B.hex()}",
             "--timeout", "1", "--poll-interval", "0.1",
             "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "unix_a" in result.output
        assert "uptime_b" in result.output
        # Per-key detection lines, each tagged with its key prefix.
        assert f"key {_PREFIX_A}" in result.output
        assert "counter_source=UNIX_TIME" in result.output
        assert f"key {_PREFIX_B}" in result.output
        assert "counter_source=DEVICE_UPTIME" in result.output


# ---------------------------------------------------------------------------
# CLI - sat scan DAY_OFFSET column
# ---------------------------------------------------------------------------


class TestSatScanDayOffsetCli:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_no_day_offset_column_without_key(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"x")
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli, ["sat", "scan", "--timeout", "1", "--poll-interval", "0.1"]
        )
        assert result.exit_code == 0
        assert "DAY_OFFSET" not in result.output

    def test_day_offset_column_shown_single_key(self, runner, monkeypatch):
        # Always shown when a key is given, even for a single key.
        pkt = _make_encrypted_sat_pkt(plaintext=b"today", time_counter=_TODAY_TC)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--timeout", "1",
             "--poll-interval", "0.1", "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "DAY_OFFSET" in result.output
        assert "today" in result.output

    def test_day_offset_previous_day_shows_minus_one(self, runner, monkeypatch):
        # Packet encrypted for yesterday but timestamped today -> offset -1.
        pkt = _make_encrypted_sat_pkt(plaintext=b"yday", time_counter=_TODAY_TC - 1)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--timeout", "1",
             "--poll-interval", "0.1", "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "yday" in result.output
        assert "-1" in result.output

    def test_day_offset_na_for_device_uptime(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"up", time_counter=5)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(), "--counter-mode",
             "DEVICE_UPTIME", "--timeout", "1", "--poll-interval", "0.1",
             "--payload-format", "string"],
        )
        assert result.exit_code == 0
        assert "up" in result.output
        assert "DAY_OFFSET" in result.output
        assert "n/a" in result.output

    def test_day_offset_na_for_failed_row(self, runner, monkeypatch):
        bad = SatellitePacket(
            device_id="0xCAFE", seq_num=1, device_type="silabs",
            timestamp=_TODAY_TC * 86400, rssi_dB=-1.0, channel_num=1,
            freq_offset_hz=0.0, payload=b"\xde\xad\xbe\xef",
            auth_tag=b"\x00\x00\x00\x00",
        )
        _patch_scan(monkeypatch, bad)
        result = runner.invoke(
            cli,
            ["sat", "scan", "--key", _MASTER_256.hex(),
             "--show-failed-decryption", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "FAIL" in result.output
        assert "n/a" in result.output

    def test_json_includes_day_offset_for_unix(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"today", time_counter=_TODAY_TC)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "-o", "json", "--key", _MASTER_256.hex(),
             "--payload-format", "string", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert '"day_offset": 0' in result.output

    def test_json_omits_day_offset_for_device_uptime(self, runner, monkeypatch):
        pkt = _make_encrypted_sat_pkt(plaintext=b"up", time_counter=5)
        _patch_scan(monkeypatch, pkt)
        result = runner.invoke(
            cli,
            ["sat", "scan", "-o", "json", "--key", _MASTER_256.hex(),
             "--counter-mode", "DEVICE_UPTIME", "--payload-format", "string",
             "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "up" in result.output
        assert "day_offset" not in result.output
