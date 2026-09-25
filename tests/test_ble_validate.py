"""Tests for ble validate command helpers."""
import uuid
import base64

import time
import pytest
from unittest.mock import patch
from click.testing import CliRunner

from hubblenetwork.errors import (
    BackendError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
)
from hubblenetwork.device import Device
from hubblenetwork.packets import DecryptedPacket, UnencryptedPacket
from tests.fake_packets import as_packet, make_ctr, make_eax

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

    def test_accepts_valid_inputs_then_fails_on_credentials(self, monkeypatch):
        """Valid key+uuid should pass step 1, then fail at step 2 (no creds)."""
        monkeypatch.delenv("HUBBLE_ORG_ID", raising=False)
        monkeypatch.delenv("HUBBLE_API_TOKEN", raising=False)
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.ble_mod") as mock_ble:
            result = CliRunner().invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
            ])
        assert "Validating format of inputs" in result.output
        assert result.exit_code == 1
        # Same guidance as every other command: export hint plus a flag form
        # that is a real `ble validate` invocation.
        assert "HUBBLE_ORG_ID and HUBBLE_API_TOKEN not set" in result.output
        assert "export HUBBLE_ORG_ID=<your org id>" in result.output
        assert "export HUBBLE_API_TOKEN=<your api token>" in result.output
        assert (
            "hubblenetwork ble validate --device-id <id> --org-id <id> --token <token>"
            in result.output
        )
        mock_ble.scan.assert_not_called()

    def test_only_token_missing_names_it(self, monkeypatch):
        monkeypatch.delenv("HUBBLE_API_TOKEN", raising=False)
        result = CliRunner().invoke(cli, [
            "ble", "validate", "--device-id", str(uuid.uuid4()), "--org-id", "o",
        ])
        assert result.exit_code == 1
        assert "HUBBLE_API_TOKEN not set" in result.output
        assert "HUBBLE_ORG_ID and" not in result.output


KEY = bytes(range(32))
EAX_KEY = bytes(range(16))
DEVICE_ID = "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"


def _ctr_pkts(n=2, key=KEY, **kw):
    return [as_packet(make_ctr(key, b"hello", seq_no=i, **kw)) for i in range(n)]


def _decoded(device_id=DEVICE_ID, name="dev-a", ts=None):
    return DecryptedPacket(
        timestamp=ts or int(time.time()),
        device_id=device_id,
        device_name=name,
        location=None,
        tags={},
        payload=b"hello",
        rssi=-60,
        counter=12,
        sequence=3,
    )


def _invoke(pkts, results=None, *, key=None, decode_error=None, get_device=None,
            device_id=DEVICE_ID):
    args = ["ble", "validate", "--device-id", device_id,
            "--org-id", "fake-org", "--token", "fake-token"]
    if key is not None:
        args += ["--key", key]
    with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
         patch("hubblenetwork.cli.ble_mod") as mock_ble:
        org = mock_org_cls.return_value
        mock_ble.scan.return_value = pkts
        if decode_error is not None:
            org.decode_packets.side_effect = decode_error
        else:
            org.decode_packets.side_effect = lambda ps: (
                results if results is not None else [None] * len(ps)
            )
        if isinstance(get_device, Exception):
            org.get_device.side_effect = get_device
        else:
            org.get_device.return_value = get_device or Device(id=DEVICE_ID, name="dev-a")
        result = CliRunner().invoke(cli, args)
    return result, org, mock_ble


class TestBleValidateFlow:
    def test_key_is_optional_and_success_prints_metadata(self):
        pkts = _ctr_pkts(2)
        result, org, _ = _invoke(pkts, [None, _decoded()])
        assert result.exit_code == 0, result.output
        assert "[COMPLETE]" in result.output
        assert '"dev-a"' in result.output
        assert "hello" in result.output
        assert "sequence: 3" in result.output
        assert "counter:  12" in result.output
        assert "1 of 2 packet(s)" in result.output
        # Only encrypted packets are sent, and no local decrypt step ran.
        assert org.decode_packets.call_args.args[0] == pkts
        assert "Validating encryption" not in result.output
        org.list_devices.assert_not_called()

    def test_device_id_matches_without_hyphens(self):
        result, org, _ = _invoke(_ctr_pkts(1), [_decoded()],
                                 device_id=DEVICE_ID.replace("-", "").upper())
        assert result.exit_code == 0, result.output
        # The lookup uses the canonical hyphenated form.
        org.get_device.assert_called_once_with(DEVICE_ID)

    def test_only_encrypted_packets_are_sent(self):
        unenc = UnencryptedPacket(0, None, 5, 1, b"x", -50)
        enc = _ctr_pkts(1)
        result, org, _ = _invoke([unenc] + enc, [_decoded()])
        assert result.exit_code == 0, result.output
        assert org.decode_packets.call_args.args[0] == enc

    def test_no_ble_packets_error(self):
        result, org, _ = _invoke([])
        assert result.exit_code != 0
        assert "No Hubble advertisements found" in result.output
        org.decode_packets.assert_not_called()

    def test_only_unencrypted_packets_error(self):
        result, _, _ = _invoke([UnencryptedPacket(0, None, 5, 1, b"x", -50)])
        assert result.exit_code != 0
        assert "none were encrypted" in result.output
        assert "debug tips" in result.output

    def test_cloud_did_not_decrypt_this_device(self):
        other = _decoded(device_id="11111111-2222-3333-4444-555555555555", name="other")
        result, org, _ = _invoke(_ctr_pkts(2), [None, other])
        assert result.exit_code == 1
        assert "none of them from this device" in result.output
        assert "other" in result.output
        # Registered was already established before the scan; no second lookup.
        org.get_device.assert_called_once_with(DEVICE_ID)
        assert "not found in this organization" not in result.output

    def test_success_shows_registered_device_name(self):
        result, _, _ = _invoke(_ctr_pkts(1), [_decoded()])
        assert result.exit_code == 0, result.output
        assert "Checking device is registered to this organization... [SUCCESS]" in (
            result.output
        )
        assert 'Device name: "dev-a"' in result.output

    def test_unknown_device_fails_before_scan(self):
        result, org, mock_ble = _invoke(
            _ctr_pkts(1), get_device=NotFoundError("404: nope")
        )
        assert result.exit_code == 1
        assert "Checking device is registered to this organization... [ERROR]" in (
            result.output
        )
        assert "Device ID not found in this organization" in result.output
        assert "org list-devices" in result.output
        mock_ble.scan.assert_not_called()
        org.decode_packets.assert_not_called()
        assert "Scanning" not in result.output

    @pytest.mark.parametrize(
        "error,expected",
        [
            (PermissionDeniedError("403: lacks scope"), "403: lacks scope"),
            (RateLimitError("429: slow"), "rate-limiting"),
            (BackendError("500: x"), "Unable to look up the device in the Hubble Cloud"),
        ],
    )
    def test_device_lookup_backend_errors_are_clean(self, error, expected):
        result, _, mock_ble = _invoke(_ctr_pkts(1), get_device=error)
        assert result.exit_code == 1
        assert expected in result.output
        assert "Traceback" not in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)
        mock_ble.scan.assert_not_called()

    @pytest.mark.parametrize(
        "error,expected",
        [
            (PermissionDeniedError("lacks the 'read-packets' scope"), "read-packets"),
            (RateLimitError("429: slow"), "rate-limiting"),
            (BackendError("500: boom"), "Unable to decode packets in the cloud"),
        ],
    )
    def test_backend_errors_are_clean(self, error, expected):
        result, _, _ = _invoke(_ctr_pkts(1), decode_error=error)
        assert result.exit_code == 1
        assert expected in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)

    def test_invalid_credentials(self):
        from hubblenetwork import InvalidCredentialsError

        with patch("hubblenetwork.cli.Organization",
                   side_effect=InvalidCredentialsError("bad")):
            result = CliRunner().invoke(cli, [
                "ble", "validate", "--device-id", DEVICE_ID,
                "--org-id", "o", "--token", "t",
            ])
        assert result.exit_code == 1
        assert "Validating organization credentials... [ERROR]" in result.output
        assert "rejected the org ID and token" in result.output
        assert "hubblenetwork validate-credentials" in result.output


class TestBleValidateWithKey:
    def test_unix_time_eid_reported(self):
        result, _, _ = _invoke(_ctr_pkts(1), [_decoded()], key=KEY.hex())
        assert result.exit_code == 0, result.output
        assert "EID type: UNIX_TIME" in result.output

    def test_device_uptime_eid_reported(self):
        result, _, _ = _invoke(_ctr_pkts(1, time_counter=42), [_decoded()], key=KEY.hex())
        assert result.exit_code == 0, result.output
        assert "EID type: DEVICE_UPTIME" in result.output
        assert "counter=42" in result.output

    def test_eax_decrypts_locally_with_exponent(self):
        pkt = as_packet(make_eax(EAX_KEY, b"e", index=2, period_exponent=10))
        result, _, _ = _invoke([pkt], [_decoded()], key=EAX_KEY.hex())
        assert result.exit_code == 0, result.output
        assert "AES-128-EAX" in result.output
        assert "period_exponent=10" in result.output

    def test_wrong_key_still_fails(self):
        result, org, _ = _invoke(_ctr_pkts(1), [_decoded()], key=bytes(32).hex())
        assert result.exit_code == 1
        assert "Unable to decrypt packet with given device key" in result.output
        org.decode_packets.assert_not_called()

    def test_decryption_failure_error(self):
        with patch("hubblenetwork.detect.decrypt", return_value=None):
            result, _, _ = _invoke(_ctr_pkts(1), key=KEY.hex())
        assert result.exit_code != 0
        assert "Unable to decrypt packet" in result.output

    def test_key_ok_but_cloud_disagrees_mentions_registration(self):
        result, _, _ = _invoke(_ctr_pkts(1), [None], key=KEY.hex())
        assert result.exit_code == 1
        assert "decrypts packets locally" in result.output
