"""Tests for ble validate command helpers."""
import uuid
import base64

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from hubblenetwork.cli import (
    _validate_info,
    _validate_success,
    _validate_error,
    _detect_eid_type,
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

    def test_rejects_invalid_pool_size(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        result = runner.invoke(cli, [
            "ble", "validate",
            "--key", key,
            "--device-id", str(uuid.uuid4()),
            "--pool-size", "7",
        ])
        assert result.exit_code != 0
        assert "Invalid --pool-size" in result.output


class TestBleValidateErrorPaths:
    """Test error handling for validation steps 4-6 using mocks."""

    def test_unregistered_device_error(self):
        """Step 4: device ID absent from list_devices response."""
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org = mock_org_cls.return_value
            mock_org.list_devices.return_value = []
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "Device ID not found" in result.output

    def test_no_ble_packets_error(self):
        """Step 5: Error when BLE scan returns no packets."""
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble:
            mock_org = mock_org_cls.return_value
            mock_org.list_devices.return_value = [MagicMock(id=device_id)]
            mock_ble.scan.return_value = []
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "No Hubble advertisements found" in result.output

    def test_decryption_failure_error(self):
        """Step 6: Error when no packet can be decrypted."""
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.cli.decrypt") as mock_decrypt:
            mock_org = mock_org_cls.return_value
            mock_org.list_devices.return_value = [MagicMock(id=device_id)]
            mock_ble.scan.return_value = [object()]
            mock_decrypt.return_value = None
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "Unable to decrypt packet" in result.output


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


class TestDetectEidType:
    """Unit tests for the _detect_eid_type helper."""

    def test_epoch_only(self):
        pkt = MagicMock()
        mock_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return None if "eid_pool_size" in kwargs else mock_dec

        with patch("hubblenetwork.cli.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt], pool_size=1024)

        assert enc is pkt
        assert dec is mock_dec
        assert label == "EPOCH_TIME"
        assert ambiguous is False

    def test_counter_only(self):
        pkt = MagicMock()
        mock_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return mock_dec if "eid_pool_size" in kwargs else None

        with patch("hubblenetwork.cli.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt], pool_size=1024)

        assert enc is pkt
        assert dec is mock_dec
        assert label == "DEVICE_UPTIME"
        assert ambiguous is False

    def test_ambiguous(self):
        pkt = MagicMock()
        epoch_dec = MagicMock()
        counter_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return counter_dec if "eid_pool_size" in kwargs else epoch_dec

        with patch("hubblenetwork.cli.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt], pool_size=1024)

        assert enc is pkt
        assert dec is epoch_dec  # epoch preferred
        assert label == "AMBIGUOUS"
        assert ambiguous is True

    def test_neither(self):
        pkt = MagicMock()

        with patch("hubblenetwork.cli.decrypt", return_value=None):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt], pool_size=1024)

        assert enc is None
        assert dec is None
        assert label is None
        assert ambiguous is False

    def test_stops_early_when_both_found(self):
        """Helper stops after pkts[0] resolves both modes; pkts[1] is never processed."""
        pkt0 = MagicMock()
        pkt1 = MagicMock()

        with patch("hubblenetwork.cli.decrypt", return_value=MagicMock()) as mock_decrypt:
            enc, dec, label, ambiguous = _detect_eid_type(
                b"k" * 16, [pkt0, pkt1], pool_size=1024
            )

        # Both modes resolved on pkt0: 1 epoch call + 1 counter call = 2 total
        assert mock_decrypt.call_count == 2
        assert enc is pkt0
        assert label == "AMBIGUOUS"
        assert ambiguous is True

    def test_advances_to_next_packet_when_first_fails(self):
        """Loop continues past pkts[0] when it fails both modes."""
        pkt0 = MagicMock()
        pkt1 = MagicMock()
        mock_dec = MagicMock()

        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            # pkt0 always fails; pkt1 succeeds epoch only
            if args[1] is pkt0:
                return None
            return None if "eid_pool_size" in kwargs else mock_dec

        with patch("hubblenetwork.cli.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt0, pkt1], pool_size=1024)

        assert enc is pkt1
        assert dec is mock_dec
        assert label == "EPOCH_TIME"
        assert ambiguous is False


class TestBleValidateEidOutput:
    """Integration tests verifying EID type is echoed in Step 6 output."""

    def test_epoch_eid_reported(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())

        def decrypt_side_effect(*args, **kwargs):
            return MagicMock(counter=20172) if "eid_pool_size" not in kwargs else None

        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.cli.decrypt", side_effect=decrypt_side_effect), \
             patch("hubblenetwork.cli.time.sleep"), \
             patch("hubblenetwork.cli._get_pkt_from_be_with_timestamp",
                   return_value=MagicMock(device_name="n", payload=b"p", sequence=1)):
            mock_org = mock_org_cls.return_value
            mock_org.list_devices.return_value = [MagicMock(id=device_id)]
            mock_ble.scan.return_value = [MagicMock()]
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])

        assert "EID type: EPOCH_TIME" in result.output
        assert "20172" in result.output

    def test_counter_eid_reported(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())

        def decrypt_side_effect(*args, **kwargs):
            return MagicMock(counter=42) if "eid_pool_size" in kwargs else None

        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.cli.decrypt", side_effect=decrypt_side_effect), \
             patch("hubblenetwork.cli.time.sleep"), \
             patch("hubblenetwork.cli._get_pkt_from_be_with_timestamp",
                   return_value=MagicMock(device_name="n", payload=b"p", sequence=1)):
            mock_org = mock_org_cls.return_value
            mock_org.list_devices.return_value = [MagicMock(id=device_id)]
            mock_ble.scan.return_value = [MagicMock()]
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])

        assert "EID type: DEVICE_UPTIME" in result.output
        assert "counter=42" in result.output
