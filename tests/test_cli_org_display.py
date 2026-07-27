"""Presentation and stream contracts for the `org` command group.

These lock the behaviour the display/flow pass changed on purpose:
  - tabular output streams through iter_packets/iter_devices, never buffering
  - json and csv stay byte-stable, so the tabular 'auto' payload default
    must not leak into them
  - stdout carries rows only; headings, progress and summaries go to stderr
  - `--help` is reachable without credentials
  - list_devices()/retrieve_packets() still return lists (SDK contract)
"""

import base64
import json
import re
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from hubblenetwork.cli import cli
from hubblenetwork.device import Device
from hubblenetwork.org import Organization
from hubblenetwork.packets import DecryptedPacket, Location

ANSI = re.compile(r"\033\[[0-9;]*m")
CREDS = ["org", "--org-id", "fake-org", "--token", "fake-token"]
REAL_LOC = Location(lat=37.761392, lon=-122.439889)


def _pkt(i=0, payload=b"\x01\x90\x9e\x39", rssi=-75, loc=REAL_LOC):
    return DecryptedPacket(
        timestamp=1785104847 + i * 7,
        device_id="dev-abc",
        device_name="unit-7",
        location=loc,
        tags={},
        payload=payload,
        rssi=rssi,
        counter=20660,
        sequence=611 + i,
    )


def _dev(i=0, name="", active=True, tags=None):
    return Device(
        id=f"{i:08d}-c1e5-4768-bb0c-568386caecca",
        name=name,
        tags={"_env": "production"} if tags is None else tags,
        created_ts=1716967547 + i * 86400,
        active=active,
    )


def _run_packets(args, packets):
    """Invoke `org get-packets` with iter_packets mocked."""
    with patch("hubblenetwork.cli.Organization") as cls:
        org = MagicMock(spec=Organization)
        org.name = "HubbleNetwork"
        org.iter_packets.side_effect = lambda *a, **k: iter(packets)
        cls.return_value = org
        res = CliRunner().invoke(cli, [*CREDS, "get-packets", "dev-abc", *args])
    return res


def _run_devices(args, devices):
    with patch("hubblenetwork.cli.Organization") as cls:
        org = MagicMock(spec=Organization)
        org.name = "HubbleNetwork"
        org.iter_devices.side_effect = lambda *a, **k: iter(devices)
        cls.return_value = org
        res = CliRunner().invoke(cli, [*CREDS, "list-devices", *args])
    return res


class TestHelpWithoutCredentials:
    """The org group used to build an Organization (two network calls) in its
    callback, so `--help` failed with exit 2 for anyone without valid creds."""

    @pytest.mark.parametrize(
        "sub", ["info", "list-devices", "get-packets", "register-device"]
    )
    def test_subcommand_help_needs_no_credentials(self, sub, monkeypatch):
        monkeypatch.delenv("HUBBLE_ORG_ID", raising=False)
        monkeypatch.delenv("HUBBLE_API_TOKEN", raising=False)
        with patch("hubblenetwork.cli.Organization") as cls:
            cls.side_effect = AssertionError("must not construct Organization for --help")
            res = CliRunner().invoke(cli, ["org", sub, "--help"])
        assert res.exit_code == 0
        assert "Usage:" in res.stdout

    def test_group_help_needs_no_credentials(self, monkeypatch):
        monkeypatch.delenv("HUBBLE_ORG_ID", raising=False)
        monkeypatch.delenv("HUBBLE_API_TOKEN", raising=False)
        res = CliRunner().invoke(cli, ["org", "--help"])
        assert res.exit_code == 0


class TestStreaming:
    def test_tabular_packets_use_the_generator(self):
        """Buffering the whole window is what caused 14.9s of silence."""
        with patch("hubblenetwork.cli.Organization") as cls:
            org = MagicMock(spec=Organization)
            org.iter_packets.side_effect = lambda *a, **k: iter([_pkt()])
            cls.return_value = org
            res = CliRunner().invoke(cli, [*CREDS, "get-packets", "dev-abc"])
        assert res.exit_code == 0
        assert org.iter_packets.called
        assert not org.retrieve_packets.called

    def test_tabular_devices_use_the_generator(self):
        with patch("hubblenetwork.cli.Organization") as cls:
            org = MagicMock(spec=Organization)
            org.name = "HubbleNetwork"
            org.iter_devices.side_effect = lambda *a, **k: iter([_dev()])
            cls.return_value = org
            res = CliRunner().invoke(cli, [*CREDS, "list-devices"])
        assert res.exit_code == 0
        assert org.iter_devices.called
        assert not org.list_devices.called


class TestSdkContract:
    def test_retrieve_packets_still_returns_a_list(self):
        org = MagicMock(spec=Organization)
        org.iter_packets.side_effect = lambda *a, **k: iter([_pkt(), _pkt(1)])
        out = Organization.retrieve_packets(org, Device(id="dev-abc"))
        assert isinstance(out, list)
        assert len(out) == 2

    def test_list_devices_still_returns_a_list(self):
        org = MagicMock(spec=Organization)
        org.iter_devices.side_effect = lambda *a, **k: iter([_dev(), _dev(1)])
        out = Organization.list_devices(org)
        assert isinstance(out, list)
        assert len(out) == 2

    def test_iter_packets_reports_pages(self):
        api = {
            "packets": [
                {
                    "device": {
                        "timestamp": 1700000000, "id": "dev-abc", "name": "n",
                        "tags": {}, "payload": base64.b64encode(b"\xde\xad").decode(),
                        "rssi": -65, "counter": 1, "sequence_number": 0,
                    },
                    "location": {"latitude": 1.0, "longitude": 2.0},
                }
            ]
        }
        org = MagicMock(spec=Organization)
        org.credentials = MagicMock()
        org.env = MagicMock()
        seen = []
        with patch("hubblenetwork.org.cloud.retrieve_packets", return_value=(api, None)):
            list(
                Organization.iter_packets(
                    org, Device(id="d"), on_page=lambda p, t: seen.append((p, t))
                )
            )
        assert seen == [(1, 1)]


class TestPayloadFormatDefaults:
    def test_tabular_defaults_to_auto(self):
        res = _run_packets([], [_pkt(payload=b"T=21.4")])
        assert "T=21.4" in res.stdout
        assert "VD0yMS40" not in res.stdout

    def test_tabular_binary_payload_is_hex(self):
        res = _run_packets([], [_pkt(payload=b"\x01\x90\x9e\x39")])
        assert "01909E39" in res.stdout

    def test_json_keeps_base64_default(self):
        res = _run_packets(["-o", "json"], [_pkt(payload=b"T=21.4")])
        assert json.loads(res.stdout)[0]["payload"] == base64.b64encode(b"T=21.4").decode()

    def test_csv_keeps_base64_default(self):
        res = _run_packets(["-o", "csv"], [_pkt(payload=b"T=21.4")])
        assert base64.b64encode(b"T=21.4").decode() in res.stdout

    def test_explicit_format_wins_on_tabular(self):
        res = _run_packets(["--payload-format", "base64"], [_pkt(payload=b"T=21.4")])
        assert "VD0yMS40" in res.stdout


class TestStreamDiscipline:
    def test_rows_on_stdout_chrome_on_stderr(self):
        res = _run_packets([], [_pkt(), _pkt(1)])
        assert "Packets" in res.stderr
        assert "Packets" not in res.stdout
        assert "2 packets" in res.stderr
        assert "2 packets" not in res.stdout
        assert "01909E39" in res.stdout

    def test_device_chrome_on_stderr(self):
        res = _run_devices([], [_dev(), _dev(1)])
        assert "Devices" in res.stderr
        assert "Devices" not in res.stdout
        assert "2 devices" in res.stderr

    def test_json_stdout_is_pure(self):
        res = _run_devices(["-f", "json"], [_dev()])
        assert json.loads(res.stdout)  # chrome would break the parse

    def test_no_ansi_when_piped(self):
        res = _run_packets([], [_pkt()])
        assert ANSI.search(res.stdout) is None


class TestAlignment:
    @staticmethod
    def _rule_and_rows(stdout):
        rules = [
            ANSI.sub("", ln) for ln in stdout.splitlines() if set(ln.strip()) == {"─"}
        ]
        return rules, stdout.splitlines()

    def test_no_packet_row_exceeds_its_rule(self):
        res = _run_packets([], [_pkt(payload=bytes(range(30)))])
        rules, lines = self._rule_and_rows(res.stdout)
        assert rules
        for line in lines:
            assert len(ANSI.sub("", line).rstrip()) <= len(rules[0])

    def test_no_device_row_exceeds_its_rule(self):
        res = _run_devices([], [_dev(name="a" * 40)])
        rules, lines = self._rule_and_rows(res.stdout)
        assert rules
        for line in lines:
            assert len(ANSI.sub("", line).rstrip()) <= len(rules[0])

    def test_default_packet_table_fits_eighty_columns(self):
        res = _run_packets([], [_pkt()])
        widths = [len(ANSI.sub("", ln).rstrip()) for ln in res.stdout.splitlines()]
        assert max(widths) <= 80

    def test_device_table_fits_eighty_columns(self):
        res = _run_devices([], [_dev(name="field-unit-7")])
        widths = [len(ANSI.sub("", ln).rstrip()) for ln in res.stdout.splitlines()]
        assert max(widths) <= 80

    def test_rows_carry_no_trailing_padding(self):
        res = _run_packets([], [_pkt()])
        for line in res.stdout.splitlines():
            assert line == line.rstrip(), repr(line)


class TestLimitDeclaresWhatItHid:
    def test_packets_limit_is_off_by_default(self):
        res = _run_packets([], [_pkt(i) for i in range(5)])
        assert "5 packets" in res.stderr
        assert "--limit" not in res.stderr

    def test_packets_limit_truncates_and_says_so(self):
        res = _run_packets(["-n", "2"], [_pkt(i) for i in range(5)])
        assert "2 packets" in res.stderr
        assert "Stopped at --limit 2" in res.stderr

    def test_devices_limit_truncates_and_says_so(self):
        res = _run_devices(["-n", "2"], [_dev(i) for i in range(5)])
        assert "2 devices shown" in res.stderr
        assert "More were not listed" in res.stderr

    def test_devices_limit_suppresses_unknowable_tallies(self):
        """With a limit we never saw the whole org, so org-wide counts are unknown."""
        res = _run_devices(["-n", "2"], [_dev(i) for i in range(5)])
        assert "unnamed" not in res.stderr
        assert "tags:" not in res.stderr


class TestDebugColumns:
    def test_default_omits_forensic_columns(self):
        res = _run_packets([], [_pkt()])
        for header in ("EPOCH", "CTR", "SEQ"):
            assert header not in res.stdout

    def test_debug_adds_forensic_columns(self):
        res = _run_packets(["--debug"], [_pkt()])
        for header in ("EPOCH", "CTR", "SEQ"):
            assert header in res.stdout
        assert "1785104847" in res.stdout
        assert "20660" in res.stdout


class TestSummaries:
    def test_packet_summary_reports_rssi_range(self):
        res = _run_packets([], [_pkt(0, rssi=-75), _pkt(1, rssi=-87)])
        assert "RSSI -75 to -87 dBm" in res.stderr

    def test_day_phrase_is_singular_for_one(self):
        res = _run_packets(["--days", "1"], [_pkt()])
        assert "last 1 day" in res.stderr
        assert "last 1 days" not in res.stderr

    def test_uniform_tags_reported_once_not_per_row(self):
        res = _run_devices([], [_dev(i) for i in range(4)])
        assert res.stdout.count("_env") == 0
        assert "tags: _env=production" in res.stderr

    def test_device_tallies_reconcile(self):
        devs = [_dev(0, name="a"), _dev(1), _dev(2, active=False), _dev(3)]
        res = _run_devices([], devs)
        line = next(ln for ln in res.stderr.splitlines() if re.match(r"^\d+ devices", ln))
        assert "4 devices" in line
        assert "3 unnamed" in line
        assert "1 inactive" in line

    def test_all_active_is_stated_positively(self):
        res = _run_devices([], [_dev(0, name="a"), _dev(1, name="b")])
        assert "all active" in res.stderr


class TestEmptyStates:
    def test_no_packets_names_the_window_and_the_flag(self):
        res = _run_packets(["--days", "30"], [])
        assert res.exit_code == 0
        assert "No packets in the last 30 days" in res.stderr
        assert "--days 90" in res.stderr
        assert res.stdout == ""

    def test_no_devices_names_a_next_action(self):
        res = _run_devices([], [])
        assert "No devices registered" in res.stderr
        assert "register-device" in res.stderr

    def test_empty_json_is_still_an_array(self):
        res = _run_devices(["-f", "json"], [])
        assert json.loads(res.stdout) == []


class TestOrgInfo:
    def test_no_dataclass_repr_leaks(self):
        with patch("hubblenetwork.cli.Organization") as cls:
            org = MagicMock(spec=Organization)
            org.name = "HubbleNetwork"
            org.org_id = "7e93b204-3f5d-470e-b32d-a4521471d248"
            org.env = MagicMock(name="PROD")
            org.env.name = "PROD"
            org.env.url = "https://api.hubble.com"
            cls.return_value = org
            res = CliRunner().invoke(cli, [*CREDS, "info"])
        assert res.exit_code == 0
        assert "Environment(" not in res.stdout
        assert "HubbleNetwork" in res.stdout
        assert "PROD" in res.stdout
        assert "https://api.hubble.com" in res.stdout
