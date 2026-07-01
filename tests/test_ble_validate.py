"""Tests for ble validate command helpers."""
import uuid
import base64

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from hubblenetwork import Device
from hubblenetwork.packets import AesEaxPacket, EncryptedPacket
from hubblenetwork.cli import (
    _validate_info,
    _validate_success,
    _validate_error,
    cli,
)
class TestValidateHelpers:
    def test_validate_info_prints_cyan_info_tag(self, capsys):
        _validate_info("Testing something")
        captured = capsys.readouterr()
        assert "Testing something..." in captured.out

    def test_validate_success_prints_green_success_tag(self, capsys):
        _validate_success()
        captured = capsys.readouterr()
        assert "SUCCESS" in captured.out

    def test_validate_error_prints_and_exits(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _validate_error("Something broke")
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "ERROR" in captured.out
        assert "Something broke" in captured.out


class TestBleValidateInputs:
    """Test input validation (step 1 of the validate flow)."""

    def test_rejects_invalid_base64_key(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "ble", "validate",
            "--key", "not-valid-base64!!!",
            "--device-id", str(uuid.uuid4()),
        ])
        assert result.exit_code != 0
        assert "Incorrectly formatted device key" in result.output

    def test_rejects_invalid_uuid(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        result = runner.invoke(cli, [
            "ble", "validate",
            "--key", key,
            "--device-id", "not-a-uuid",
        ])
        assert result.exit_code != 0
        assert "Device UUID formatted incorrectly" in result.output

    def test_accepts_valid_inputs_then_fails_on_credentials(self):
        """Valid key+uuid should pass step 1, then fail at step 2 (no creds)."""
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        result = runner.invoke(cli, [
            "ble", "validate",
            "--key", key,
            "--device-id", device_id,
        ])
        assert "Validating format of inputs" in result.output


class TestBleValidateErrorPaths:
    """Steps 4-6 error handling."""

    def test_unregistered_device_error(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org = mock_org_cls.return_value
            mock_org.get_device.return_value = None
            result = runner.invoke(cli, [
                "ble", "validate", "--key", key, "--device-id", device_id,
                "--org-id", "fake-org", "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "Device ID not found" in result.output

    def test_no_ble_packets_error(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble:
            mock_org = mock_org_cls.return_value
            mock_org.get_device.return_value = Device(id=device_id)
            mock_ble.scan.return_value = []
            result = runner.invoke(cli, [
                "ble", "validate", "--key", key, "--device-id", device_id,
                "--org-id", "fake-org", "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "No Hubble advertisements found" in result.output

    def test_decryption_failure_error(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.detect.decrypt", return_value=None):
            mock_org = mock_org_cls.return_value
            mock_org.get_device.return_value = Device(id=device_id)
            mock_ble.scan.return_value = [MagicMock(spec=EncryptedPacket)]
            result = runner.invoke(cli, [
                "ble", "validate", "--key", key, "--device-id", device_id,
                "--org-id", "fake-org", "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "Unable to decrypt packet" in result.output


class TestBleValidateConfigCheck:
    """Step 7: detected-config vs backend-config comparison."""

    def _run(self, *, device, decrypt_side_effect, key_bytes=b"a" * 16):
        runner = CliRunner()
        key = base64.b64encode(key_bytes).decode()
        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.detect.decrypt", side_effect=decrypt_side_effect), \
             patch("hubblenetwork.cli.time.sleep"), \
             patch("hubblenetwork.cli._get_pkt_from_be_with_timestamp",
                   return_value=MagicMock(device_name="n", payload=b"p", sequence=1)):
            mock_org = mock_org_cls.return_value
            mock_org.get_device.return_value = device
            pkt_mock = MagicMock(spec=EncryptedPacket)
            # EncryptedPacket is a frozen dataclass, so its fields aren't in the class dir():
            # a spec'd MagicMock won't auto-create `timestamp`, which the retrieve step reads
            # from pkt_to_ingest. Set it explicitly.
            pkt_mock.timestamp = 12345
            mock_ble.scan.return_value = [pkt_mock]
            return mock_org, runner.invoke(cli, [
                "ble", "validate", "--key", key, "--device-id", device.id,
                "--org-id", "fake-org", "--token", "fake-token",
            ])

    def test_config_match_passes_and_ingests(self):
        device = Device(id=str(uuid.uuid4()), encryption="AES-128-CTR",
                        counter_source="UNIX_TIME")

        def unix(*a, **kw):
            return None if kw.get("counter_mode") == "DEVICE_UPTIME" else MagicMock(counter=20172)

        mock_org, result = self._run(device=device, decrypt_side_effect=unix)
        assert result.exit_code == 0
        assert "counter_source: OK" in result.output
        assert "encryption: OK" in result.output
        assert "All validation steps passed" in result.output
        assert mock_org.ingest_packet.called

    def test_counter_source_mismatch_fails(self):
        device = Device(id=str(uuid.uuid4()), encryption="AES-128-CTR",
                        counter_source="DEVICE_UPTIME")

        def unix(*a, **kw):
            return None if kw.get("counter_mode") == "DEVICE_UPTIME" else MagicMock(counter=1)

        mock_org, result = self._run(device=device, decrypt_side_effect=unix)
        assert result.exit_code != 0
        assert "does not match the backend" in result.output
        assert "counter_source: FAIL" in result.output
        assert not mock_org.ingest_packet.called

    def test_backend_omits_config_skips_and_continues(self):
        device = Device(id=str(uuid.uuid4()))  # encryption/counter_source None

        def unix(*a, **kw):
            return None if kw.get("counter_mode") == "DEVICE_UPTIME" else MagicMock(counter=1)

        mock_org, result = self._run(device=device, decrypt_side_effect=unix)
        assert result.exit_code == 0
        assert "comparison skipped" in result.output
        assert mock_org.ingest_packet.called

    def test_eax_device_validates_config_then_skips_ingest(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device = Device(id=str(uuid.uuid4()), encryption="AES-128-EAX",
                        counter_source="DEVICE_UPTIME", period_exponent=5)

        def eax(key_arg, pkt, period_exponent=0):
            return MagicMock(counter=3) if period_exponent == 5 else None

        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.detect.decrypt_eax", side_effect=eax):
            mock_org = mock_org_cls.return_value
            mock_org.get_device.return_value = device
            mock_ble.scan.return_value = [MagicMock(spec=AesEaxPacket)]
            result = runner.invoke(cli, [
                "ble", "validate", "--key", key, "--device-id", device.id,
                "--org-id", "fake-org", "--token", "fake-token",
            ])

        assert result.exit_code == 0
        assert "period_exponent: OK" in result.output
        assert "Config validation passed (EAX" in result.output
        assert not mock_org.ingest_packet.called


class TestGetPktFromBeWithTimestamp:
    def test_returns_matching_packet(self):
        from hubblenetwork.cli import _get_pkt_from_be_with_timestamp

        mock_org = MagicMock()
        mock_device = MagicMock()
        pkt1 = MagicMock(timestamp=100)
        pkt2 = MagicMock(timestamp=200)
        mock_org.retrieve_packets.return_value = [pkt1, pkt2]

        result = _get_pkt_from_be_with_timestamp(mock_org, mock_device, 200)
        assert result is pkt2

    def test_returns_none_when_no_match(self):
        from hubblenetwork.cli import _get_pkt_from_be_with_timestamp

        mock_org = MagicMock()
        mock_device = MagicMock()
        mock_org.retrieve_packets.return_value = [MagicMock(timestamp=100)]

        result = _get_pkt_from_be_with_timestamp(mock_org, mock_device, 999)
        assert result is None
