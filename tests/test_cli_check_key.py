"""`hubblenetwork check-key`: the CLI around hubblenetwork.diagnose.

The rules themselves are tested in test_diagnose.py. These lock the command's
contract: what it needs, what it prints, and that a failure exits 1 so it can
gate a script, the same as `doctor`.
"""

import re
import time
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hubblenetwork.cli import _CHECK_OK, cli
from hubblenetwork.crypto import DEVICE_UPTIME, UNIX_TIME
from hubblenetwork.errors import NotFoundError
from tests.test_diagnose import KEY, _ctr

ANSI = re.compile(r"\033\[[0-9;]*m")
KEY_HEX = KEY.hex()
TODAY = int(time.time()) // 86400


def _run(*args):
    res = CliRunner().invoke(cli, ["check-key", *args])
    return res, ANSI.sub("", res.output)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("HUBBLE_ORG_ID", "org")
    monkeypatch.setenv("HUBBLE_API_TOKEN", "tok")
    with patch("hubblenetwork.cli._doctor_bluetooth", return_value=(_CHECK_OK, "", [])):
        yield


def _device_json(counter_source=UNIX_TIME, last_ago=60, **extra):
    """A GET /devices/<id> response; last_ago=None means never decoded."""
    data = {"id": "d1", "encryption": "AES-256-CTR",
            "eid_rotation": {"counter_source": counter_source}, **extra}
    if last_ago is not None:
        data["most_recent_packet"] = {"terrestrial": {"timestamp": time.time() - last_ago}}
    return data


def _backend(device=None, missing=False):
    """Patch credentials and the device GET to return `device` (JSON)."""
    env = type("E", (), {"name": "PROD"})()
    get = (patch("hubblenetwork.cli.cloud.get_device",
                 side_effect=NotFoundError("404: unexpected response")) if missing
           else patch("hubblenetwork.cli.cloud.get_device", return_value=device))
    return patch("hubblenetwork.cli.cloud.get_env_from_credentials", return_value=env), get


def _healthy():
    return _backend(_device_json())


def _scan(stream, delivered=None):
    """Patch ble.scan with what it really does: hand each packet to `until`,
    in order, and stop as soon as it returns True."""
    delivered = [] if delivered is None else delivered

    def fake(timeout, until=None):
        for pkt in stream:
            delivered.append(pkt)
            if until is not None and until(pkt):
                break
        return list(delivered)

    return patch("hubblenetwork.cli.ble_mod.scan", side_effect=fake)


class TestInputs:
    def test_device_id_is_required(self):
        # A key alone would only repeat `ble scan`; the registration is the
        # thing every other check is compared against.
        res, out = _run("--key", KEY_HEX)
        assert res.exit_code == 2
        assert "check-key needs --device-id" in out
        assert "hubblenetwork org list-devices" in out

    def test_key_is_required(self):
        res, out = _run("-d", "d1")
        assert res.exit_code == 2
        assert "check-key needs --key" in out
        assert "org register-device" in out

    def test_firmware_is_optional(self):
        creds, get = _healthy()
        with creds, get:
            res, out = _run("-d", "d1", "-k", KEY_HEX, "-t", "0")
        assert res.exit_code == 0
        assert "Firmware" not in out

    def test_bad_key_is_a_usage_error(self):
        res, out = _run("-d", "d1", "--key", "not-a-key")
        assert res.exit_code == 2
        assert "--key" in out

    @pytest.mark.parametrize("opt", [["-o", "json"], ["--format", "json"], ["--ingest"],
                                     ["--within", "5"]])
    def test_removed_options_are_rejected(self, opt):
        res, _ = _run("-d", "d1", "-k", KEY_HEX, *opt)
        assert res.exit_code == 2


class TestOutput:
    def test_firmware_without_config_is_a_skip_not_a_failure(self, tmp_path):
        creds, get = _healthy()
        with creds, get:
            res, out = _run("-d", "d1", "-k", KEY_HEX, "-t", "0", "--firmware", str(tmp_path))
        assert res.exit_code == 0
        assert "no Hubble config found" in out
        assert "Key setup looks right." in out

    def test_timeout_zero_does_not_scan(self):
        creds, get = _healthy()
        with creds, get, patch("hubblenetwork.cli.ble_mod.scan") as scan:
            _res, out = _run("-d", "d1", "--key", KEY_HEX, "--timeout", "0")
        scan.assert_not_called()
        assert "scan disabled" in out

    def test_other_devices_are_not_counted(self):
        creds, get = _healthy()
        pkts = [_ctr(bytes(32), TODAY, s) for s in range(9)] + [_ctr(KEY, TODAY)]
        with creds, get, _scan(pkts):
            _res, out = _run("-d", "d1", "-k", KEY_HEX)
        assert "1 packet from this key: AES-256-CTR, UNIX_TIME" in out
        assert "of 10" not in out

    def test_counter_mode_mismatch_end_to_end(self):
        creds, get = _backend(_device_json(last_ago=None, name="board"))
        with creds, get, _scan([_ctr(KEY, 42, seq) for seq in range(3)]):
            res, out = _run("--key", KEY_HEX, "--device-id", "d1", "--ascii")
        assert res.exit_code == 1
        assert "registered UNIX_TIME, but the device is broadcasting DEVICE_UPTIME" in out
        assert "Key setup has problems." in out

    def test_scan_stops_at_the_first_decoded_packet(self):
        creds, get = _backend(_device_json(counter_source=DEVICE_UPTIME))
        stream = [_ctr(bytes(32), TODAY, 1), _ctr(KEY, 42, 1), _ctr(KEY, 42, 2)]
        delivered = []
        with creds, get, _scan(stream, delivered):
            res, out = _run("-d", "d1", "-k", KEY_HEX, "-t", "15")
        assert len(delivered) == 2  # never waited for the third
        assert "1 packet from this key" in out
        assert "up to 15s" in out
        assert res.exit_code == 0

    def test_unknown_device(self):
        creds, get = _backend(missing=True)
        with creds, get:
            res, out = _run("--device-id", "nope", "-k", KEY_HEX, "-t", "0")
        assert res.exit_code == 1
        assert "no device with this ID" in out
        assert "Backend" not in out

    def test_bad_credentials_skip_the_lookup(self):
        with patch("hubblenetwork.cli.cloud.get_env_from_credentials", return_value=None), \
                patch("hubblenetwork.cli.cloud.get_device") as get:
            res, out = _run("--device-id", "d1", "-k", KEY_HEX, "-t", "0")
        get.assert_not_called()
        assert res.exit_code == 1
        assert "rejected" in out
        assert "Registration" not in out

    def test_one_request_beyond_the_credentials_check(self):
        # The env from the credentials check is reused; no Organization(),
        # which would repeat it and fetch org metadata nobody reads.
        creds, get = _healthy()
        with creds as env_lookup, get as get_device, \
                patch("hubblenetwork.cli.Organization") as org:
            _run("-d", "d1", "-k", KEY_HEX, "-t", "0")
        assert env_lookup.call_count == 1
        assert get_device.call_count == 1
        org.assert_not_called()

    def test_scan_failure_is_a_row_not_a_crash(self):
        creds, get = _healthy()
        with creds, get, \
                patch("hubblenetwork.cli.ble_mod.scan", side_effect=RuntimeError("no adapter")):
            res, out = _run("-d", "d1", "--key", KEY_HEX)
        assert res.exit_code == 1
        assert "BLE scan failed (no adapter)" in out
