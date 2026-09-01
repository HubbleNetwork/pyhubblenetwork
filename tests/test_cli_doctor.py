"""`hubblenetwork doctor`: the setup validation step a reviewer found missing.

The Bluetooth check is the interesting one. Touching CoreBluetooth without an
Info.plist carrying NSBluetoothAlwaysUsageDescription is what kills the process,
so the check has to be static: it inspects the interpreter's plist rather than
attempting a scan. A probing implementation would be the very crash it reports.
"""

import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hubblenetwork import termcaps
from hubblenetwork.cli import (
    _CHECK_FAIL,
    _CHECK_OK,
    _CHECK_SKIP,
    _bluetooth_linux,
    _doctor_bluetooth,
    _doctor_credentials,
    cli,
)


def _run(args=(), env=None):
    return CliRunner().invoke(cli, ["doctor", *args], env=env)


@pytest.fixture(autouse=True)
def _no_ambient_credentials(monkeypatch):
    monkeypatch.delenv("HUBBLE_ORG_ID", raising=False)
    monkeypatch.delenv("HUBBLE_API_TOKEN", raising=False)


class TestCredentialsCheck:
    def test_unset_is_a_failure_that_names_the_variables(self):
        status, summary, advice = _doctor_credentials(None, None)
        assert status == _CHECK_FAIL
        assert "not set" in summary
        assert any("HUBBLE_ORG_ID" in line for line in advice)
        assert any("HUBBLE_API_TOKEN" in line for line in advice)

    @pytest.mark.parametrize(
        "org_id,token,missing",
        [("org", None, "HUBBLE_API_TOKEN"), (None, "tok", "HUBBLE_ORG_ID")],
    )
    def test_half_set_names_the_missing_one(self, org_id, token, missing):
        status, summary, advice = _doctor_credentials(org_id, token)
        assert status == _CHECK_FAIL
        assert missing in summary

    def test_valid_reports_the_environment(self):
        env = type("E", (), {"name": "PROD"})()
        with patch("hubblenetwork.cli.cloud.get_env_from_credentials", return_value=env):
            status, summary, _ = _doctor_credentials("org", "tok")
        assert status == _CHECK_OK
        assert "PROD" in summary

    def test_rejected_is_distinct_from_unset(self):
        with patch("hubblenetwork.cli.cloud.get_env_from_credentials", return_value=None):
            status, summary, advice = _doctor_credentials("org", "tok")
        assert status == _CHECK_FAIL
        assert "rejected" in summary
        assert not any("export" in line for line in advice)

    def test_network_trouble_is_not_reported_as_bad_credentials(self):
        with patch(
            "hubblenetwork.cli.cloud.get_env_from_credentials",
            side_effect=OSError("connection refused"),
        ):
            status, summary, _ = _doctor_credentials("org", "tok")
        assert status == _CHECK_FAIL
        assert "reach the API" in summary


class TestBluetoothCheck:
    def test_the_check_never_touches_corebluetooth(self):
        """A probing check would abort the process it is meant to diagnose."""
        with patch.dict(sys.modules, {"bleak": None}):
            status, _, _ = _doctor_bluetooth()
        assert status in (_CHECK_OK, _CHECK_FAIL, _CHECK_SKIP)

    def test_missing_usage_description_is_a_failure_naming_the_key(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("hubblenetwork.cli._bluetooth_usage_description",
                   return_value=(False, "/some/Info.plist")):
            status, summary, advice = _doctor_bluetooth()
        assert status == _CHECK_FAIL
        assert "NSBluetoothAlwaysUsageDescription" in summary
        assert any("kill" in line for line in advice)

    def test_present_usage_description_passes(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("hubblenetwork.cli._bluetooth_usage_description",
                   return_value=(True, "/some/Info.plist")):
            status, _, _ = _doctor_bluetooth()
        assert status == _CHECK_OK

    def test_uninspectable_interpreter_is_skipped_not_failed(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("hubblenetwork.cli._bluetooth_usage_description",
                   return_value=(None, "nothing found")):
            status, _, _ = _doctor_bluetooth()
        assert status == _CHECK_SKIP

    def test_unsupported_platform_is_skipped(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        status, summary, _ = _doctor_bluetooth()
        assert status == _CHECK_SKIP
        assert "win32" in summary

    def test_linux_gets_a_real_check_not_a_skip(self, monkeypatch, linux_ok):
        """Linux used to fall through to SKIP, so `doctor` had nothing to say
        to the one platform where BLE setup actually goes wrong."""
        monkeypatch.setattr(sys, "platform", "linux")
        status, _, _ = _doctor_bluetooth()
        assert status != _CHECK_SKIP


@pytest.fixture
def linux_ok(tmp_path, monkeypatch):
    """A fixture tree that looks like a healthy BlueZ box."""
    from hubblenetwork import cli as cli_mod

    sysfs = tmp_path / "bluetooth"
    (sysfs / "hci0").mkdir(parents=True)
    rfkill = tmp_path / "rfkill"
    rfkill.mkdir()
    socket = tmp_path / "system_bus_socket"
    socket.touch()

    monkeypatch.setattr(cli_mod, "_SYSFS_BLUETOOTH", str(sysfs))
    monkeypatch.setattr(cli_mod, "_SYSFS_RFKILL", str(rfkill))
    monkeypatch.setattr(cli_mod, "_DBUS_SYSTEM_SOCKET", str(socket))
    monkeypatch.delenv("DBUS_SYSTEM_BUS_ADDRESS", raising=False)
    # No 'bluetooth' group: the Arch/Fedora shape, which must not fail.
    monkeypatch.setattr("grp.getgrnam", _raise_keyerror)
    return tmp_path


def _raise_keyerror(_name):
    raise KeyError(_name)


def _add_rfkill(root, kind, value, rf_type="bluetooth"):
    entry = root / f"rfkill{len(list(root.glob('rfkill*')))}"
    entry.mkdir()
    (entry / "type").write_text(rf_type + "\n")
    for k in ("soft", "hard"):
        (entry / k).write_text(("1" if k == kind else "0") + "\n")
    return entry


class TestLinuxBluetoothCheck:
    """What `doctor` should have been telling Linux users all along.

    Every answer is read from sysfs, /run and the group database. Nothing here
    opens the adapter, for the same reason the macOS check reads a plist.
    """

    def test_healthy_box_passes(self, linux_ok):
        status, summary, _ = _bluetooth_linux()
        assert status == _CHECK_OK
        assert "hci0" in summary

    def test_no_adapter_fails(self, linux_ok, monkeypatch):
        from hubblenetwork import cli as cli_mod

        empty = linux_ok / "empty"
        empty.mkdir()
        monkeypatch.setattr(cli_mod, "_SYSFS_BLUETOOTH", str(empty))
        status, summary, fix = _bluetooth_linux()
        assert status == _CHECK_FAIL
        assert "no Bluetooth adapter" in summary
        assert any("lsusb" in line for line in fix)

    def test_soft_blocked_adapter_fails(self, linux_ok):
        _add_rfkill(linux_ok / "rfkill", "soft", 1)
        status, summary, fix = _bluetooth_linux()
        assert status == _CHECK_FAIL
        assert "soft-blocked" in summary
        assert any("rfkill unblock" in line for line in fix)

    def test_non_bluetooth_rfkill_is_ignored(self, linux_ok):
        """A blocked wifi switch says nothing about Bluetooth."""
        _add_rfkill(linux_ok / "rfkill", "soft", 1, rf_type="wlan")
        status, _, _ = _bluetooth_linux()
        assert status == _CHECK_OK

    def test_missing_dbus_socket_fails(self, linux_ok, monkeypatch):
        """The container and WSL shape: adapter fine, no system bus."""
        from hubblenetwork import cli as cli_mod

        monkeypatch.setattr(
            cli_mod, "_DBUS_SYSTEM_SOCKET", str(linux_ok / "nope")
        )
        status, summary, _ = _bluetooth_linux()
        assert status == _CHECK_FAIL
        assert "D-Bus" in summary

    def test_dbus_env_var_substitutes_for_the_default_socket(
        self, linux_ok, monkeypatch
    ):
        from hubblenetwork import cli as cli_mod

        monkeypatch.setattr(
            cli_mod, "_DBUS_SYSTEM_SOCKET", str(linux_ok / "nope")
        )
        monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/somewhere/else")
        status, _, _ = _bluetooth_linux()
        assert status == _CHECK_OK

    def test_missing_group_from_the_user_fails(self, linux_ok, monkeypatch):
        """Debian and Ubuntu gate BlueZ's D-Bus policy on this group."""
        group = type("G", (), {"gr_gid": 4242})()
        monkeypatch.setattr("grp.getgrnam", lambda _n: group)
        monkeypatch.setattr("os.getgroups", lambda: [20, 1000])
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        status, summary, fix = _bluetooth_linux()
        assert status == _CHECK_FAIL
        assert "'bluetooth' group" in summary
        assert any("usermod -aG bluetooth" in line for line in fix)

    def test_absent_group_is_not_a_failure(self, linux_ok, monkeypatch):
        """Arch and Fedora ship a polkit rule and no 'bluetooth' group at all,
        so its absence must not be reported as the Debian problem."""
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        status, _, _ = _bluetooth_linux()
        assert status == _CHECK_OK

    def test_root_is_never_told_to_join_a_group(self, linux_ok, monkeypatch):
        group = type("G", (), {"gr_gid": 4242})()
        monkeypatch.setattr("grp.getgrnam", lambda _n: group)
        monkeypatch.setattr("os.getgroups", lambda: [0])
        monkeypatch.setattr("os.geteuid", lambda: 0)
        status, _, _ = _bluetooth_linux()
        assert status == _CHECK_OK


class TestExitCode:
    def test_exits_one_when_something_needed_is_broken(self):
        res = _run()
        assert res.exit_code == 1
        assert "Not ready." in res.stdout

    def test_exits_zero_when_everything_passes(self):
        env = type("E", (), {"name": "PROD"})()
        with patch("hubblenetwork.cli.cloud.get_env_from_credentials", return_value=env), \
             patch("hubblenetwork.cli._doctor_bluetooth",
                   return_value=(_CHECK_OK, "usage description present", [])), \
             patch("hubblenetwork.cli.sat_mod.ensure_docker_available"), \
             patch("hubblenetwork.cli.sat_mod._image_exists_locally", return_value=True):
            res = _run(["--org-id", "org", "--token", "tok"])
        assert res.exit_code == 0, res.stdout
        assert "Ready to go." in res.stdout

    def test_a_skipped_check_does_not_fail_the_run(self):
        env = type("E", (), {"name": "PROD"})()
        with patch("hubblenetwork.cli.cloud.get_env_from_credentials", return_value=env), \
             patch("hubblenetwork.cli._doctor_bluetooth",
                   return_value=(_CHECK_SKIP, "not checked on linux", [])), \
             patch("hubblenetwork.cli.sat_mod.ensure_docker_available"), \
             patch("hubblenetwork.cli.sat_mod._image_exists_locally", return_value=True):
            res = _run(["--org-id", "org", "--token", "tok"])
        assert res.exit_code == 0, res.stdout
        assert "skipped" in res.stdout


class TestReport:
    def test_receiver_is_only_asked_about_when_docker_answered(self):
        res = _run()
        assert "Docker" in res.stdout
        assert "Receiver" not in res.stdout  # Docker is down on this machine

    def test_tally_reconciles_with_the_marks(self):
        import re

        res = _run()
        line = next(l for l in res.stdout.splitlines() if "ok" in l and "failed" in l)
        ok = int(re.search(r"(\d+) ok", line).group(1))
        failed = int(re.search(r"(\d+) failed", line).group(1))
        skipped_m = re.search(r"(\d+) skipped", line)
        skipped = int(skipped_m.group(1)) if skipped_m else 0
        rows = [l for l in res.stdout.splitlines() if l.startswith("  ")
                and any(l.lstrip().startswith(m) for m in ("✓", "✗", "-", "+", "x"))]
        assert ok + failed + skipped == len(rows)

    def test_respects_ascii_mode(self):
        termcaps.set_explicit_ascii(True)
        res = _run()
        assert "✗" not in res.stdout
        assert "x " in res.stdout
        assert "|" in res.stdout

    def test_appears_in_root_help_start_here(self):
        out = CliRunner().invoke(cli, ["--help"]).stdout
        assert "doctor" in out.split("Commands")[0]

    def test_help_needs_no_credentials(self):
        res = CliRunner().invoke(cli, ["doctor", "--help"])
        assert res.exit_code == 0
        assert "HUBBLE_ORG_ID" in res.stdout
