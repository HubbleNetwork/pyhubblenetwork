"""Tests for `hubblenetwork ble generate` CLI command."""

import json
import re
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from hubblenetwork.cli import cli
from hubblenetwork.crypto import decrypt, decrypt_eax, DEVICE_UPTIME
from hubblenetwork.packets import EncryptedPacket, AesEaxPacket, Location
from hubblenetwork import ble as ble_mod


_FAKE_LOCATION = Location(lat=90, lon=0, fake=True)


class TestBleGenerateHexFormat:
    def test_aes_ctr_hex_round_trips(self):
        runner = CliRunner()
        key_hex = "00" * 32
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", key_hex,
                "--payload", "deadbeef",
                "--payload-format", "hex",
                "--counter-mode", "DEVICE_UPTIME",
                "--counter", "5",
                "--seq-no", "42",
                "--format", "hex",
            ],
        )
        assert result.exit_code == 0, result.output
        hex_out = result.output.strip()
        assert re.fullmatch(r"[0-9a-fA-F]+", hex_out)
        raw = bytes.fromhex(hex_out)
        pkt = EncryptedPacket(
            timestamp=0, location=_FAKE_LOCATION, payload=raw, rssi=0,
        )
        decrypted = decrypt(bytes(32), pkt, counter_mode=DEVICE_UPTIME)
        assert decrypted is not None
        assert decrypted.payload == bytes.fromhex("deadbeef")
        assert decrypted.counter == 5
        assert decrypted.sequence == 42

    def test_aes_eax_hex_round_trips(self):
        runner = CliRunner()
        key_hex = "00" * 16
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", key_hex,
                "--payload", "deadbeef",
                "--payload-format", "hex",
                "--counter", "0",
                "--nonce-salt", "0001",
                "--period-exponent", "0",
                "--format", "hex",
            ],
        )
        assert result.exit_code == 0, result.output
        raw = bytes.fromhex(result.output.strip())
        parsed = ble_mod._make_packet(raw, rssi=0)
        assert isinstance(parsed, AesEaxPacket)
        decrypted = decrypt_eax(bytes(16), parsed, period_exponent=0)
        assert decrypted is not None
        assert decrypted.payload == bytes.fromhex("deadbeef")


class TestBleGenerateValidation:
    def test_seq_no_with_aes_eax_key_rejected(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 16,
                "--payload", "00",
                "--payload-format", "hex",
                "--seq-no", "1",
                "--format", "hex",
            ],
        )
        assert result.exit_code != 0
        assert "AES-CTR" in result.output or "16-byte" in result.output

    def test_nonce_salt_with_aes_ctr_key_rejected(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 32,
                "--payload", "00",
                "--payload-format", "hex",
                "--nonce-salt", "0001",
                "--format", "hex",
            ],
        )
        assert result.exit_code != 0
        assert "AES-EAX" in result.output or "32-byte" in result.output


class TestBleGenerateBreakdownFormat:
    def test_aes_ctr_breakdown_includes_fields(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 32,
                "--payload", "deadbeef",
                "--payload-format", "hex",
                "--counter-mode", "DEVICE_UPTIME",
                "--counter", "5",
                "--seq-no", "42",
                # no --format → default breakdown
            ],
        )
        assert result.exit_code == 0, result.output
        out = result.output
        assert "AES-CTR" in out
        assert "Service data" in out
        assert "Hex:" in out
        assert "Spaced:" in out
        assert "Python:" in out

    def test_aes_eax_breakdown_includes_fields(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 16,
                "--payload", "deadbeef",
                "--payload-format", "hex",
                "--counter", "0",
                "--nonce-salt", "0001",
                "--period-exponent", "0",
            ],
        )
        assert result.exit_code == 0, result.output
        out = result.output
        assert "AES-EAX" in out
        assert "Nonce salt" in out
        assert "Period exponent" in out
        assert "Service data" in out


class TestBleGenerateJsonFormat:
    def test_aes_ctr_json_shape(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 32,
                "--payload", "ab",
                "--payload-format", "hex",
                "--counter-mode", "DEVICE_UPTIME",
                "--counter", "5",
                "--seq-no", "42",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output.strip())
        assert data["protocol"] == "aes_ctr"
        assert data["protocol_version"] == 0
        assert data["key_length"] == 32
        assert data["counter_mode"] == "DEVICE_UPTIME"
        assert data["time_counter"] == 5
        assert data["seq_no"] == 42
        assert "eid" in data
        assert "auth_tag" in data
        assert "ciphertext" in data
        assert re.fullmatch(r"[0-9a-f]+", data["service_data"])

    def test_aes_eax_json_shape(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 16,
                "--payload", "ab",
                "--payload-format", "hex",
                "--counter", "0",
                "--nonce-salt", "0001",
                "--period-exponent", "0",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output.strip())
        assert data["protocol"] == "aes_eax"
        assert data["protocol_version"] == 2
        assert data["key_length"] == 16
        assert data["counter"] == 0
        assert data["period_exponent"] == 0
        assert data["nonce_salt"] == "0001"
        assert "eid" in data
        assert "auth_tag" in data
        assert "ciphertext" in data
        assert "service_data" in data


class TestBleGenerateIngest:
    def test_ingest_calls_organization(self, monkeypatch):
        monkeypatch.setenv("HUBBLE_ORG_ID", "test-org")
        monkeypatch.setenv("HUBBLE_API_TOKEN", "test-token")

        with patch("hubblenetwork.cli.Organization") as MockOrg:
            mock_instance = MagicMock()
            MockOrg.return_value = mock_instance

            runner = CliRunner()
            result = runner.invoke(
                cli,
                [
                    "ble", "generate",
                    "--key", "00" * 32,
                    "--payload", "ab",
                    "--payload-format", "hex",
                    "--counter-mode", "DEVICE_UPTIME",
                    "--counter", "5",
                    "--seq-no", "42",
                    "--format", "hex",
                    "--ingest",
                ],
            )

            assert result.exit_code == 0, result.output
            MockOrg.assert_called_once_with(org_id="test-org", api_token="test-token")
            mock_instance.ingest_packet.assert_called_once()
            ingested_pkt = mock_instance.ingest_packet.call_args[0][0]
            assert isinstance(ingested_pkt, EncryptedPacket)
            assert ingested_pkt.protocol_version == 0

    def test_ingest_aes_eax(self, monkeypatch):
        monkeypatch.setenv("HUBBLE_ORG_ID", "test-org")
        monkeypatch.setenv("HUBBLE_API_TOKEN", "test-token")

        with patch("hubblenetwork.cli.Organization") as MockOrg:
            mock_instance = MagicMock()
            MockOrg.return_value = mock_instance

            runner = CliRunner()
            result = runner.invoke(
                cli,
                [
                    "ble", "generate",
                    "--key", "00" * 16,
                    "--payload", "ab",
                    "--payload-format", "hex",
                    "--counter", "0",
                    "--nonce-salt", "0001",
                    "--format", "hex",
                    "--ingest",
                ],
            )

            assert result.exit_code == 0, result.output
            mock_instance.ingest_packet.assert_called_once()
            ingested_pkt = mock_instance.ingest_packet.call_args[0][0]
            assert ingested_pkt.protocol_version == 2

    def test_ingest_without_credentials_fails(self, monkeypatch):
        monkeypatch.delenv("HUBBLE_ORG_ID", raising=False)
        monkeypatch.delenv("HUBBLE_API_TOKEN", raising=False)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 32,
                "--payload", "ab",
                "--payload-format", "hex",
                "--counter-mode", "DEVICE_UPTIME",
                "--counter", "5",
                "--seq-no", "42",
                "--format", "hex",
                "--ingest",
            ],
        )
        assert result.exit_code != 0
        assert "HUBBLE_ORG_ID" in result.output
