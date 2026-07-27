"""Presentation and stream contracts for `ble scan` / `sat scan` tabular output.

These lock the behaviour the display/flow pass changed on purpose:
  - JSON keeps base64 payloads; tabular defaults to auto (text or hex)
  - stdout carries data only; scan chrome goes to stderr
  - no row is ever wider than its own rule
  - the empty state and hidden-decrypt-failure states name a next action
"""

import json
import re
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hubblenetwork.cli import (
    _fit,
    _signal_bar,
    cli,
)
from hubblenetwork.packets import (
    AesEaxPacket,
    DecryptedPacket,
    Location,
    UnencryptedPacket,
)

FAKE_LOC = Location(lat=90.0, lon=0.0, fake=True)
KEY_HEX = "a562a2f7e4c62bed52ab09633878f62b"
ANSI = re.compile(r"\033\[[0-9;]*m")


def _eax(i=0):
    return AesEaxPacket(
        timestamp=1753600000 + i * 3,
        location=FAKE_LOC,
        protocol_version=2,
        nonce_salt=bytes([0x4A + i, 0x1F]),
        eid=0x9C4E2AB77D3F0E1A + i,
        payload=bytes([0xD3, 0x07, 0x91, 0x2C, 0x66, 0xBA, 0x40, 0x18, 0xE5]),
        auth_tag=bytes([0x7B, 0x2E, 0xC1, 0x09 + i]),
        rssi=-62 - i * 4,
    )


def _decrypted(i=0, payload=b"T=21.4"):
    return DecryptedPacket(
        timestamp=1753600000 + i * 3,
        device_id="",
        device_name="",
        location=FAKE_LOC,
        tags={},
        payload=payload,
        rssi=-62 - i * 4,
        counter=20320 + i,
        sequence=None,
        protocol_version=2,
        eid=0x9C4E2AB77D3F0E1A + i,
        auth_tag=bytes([0x7B, 0x2E, 0xC1, 0x09 + i]),
    )


def _v1(nbytes=18):
    return UnencryptedPacket(
        timestamp=1753600000,
        location=FAKE_LOC,
        network_id=4378792717,
        protocol_version=1,
        payload=bytes(range(nbytes)),
        rssi=-62,
    )


def _scan(args, pkts, decrypted_for=None):
    """Invoke `ble scan` over a fixed packet list.

    decrypted_for maps eid -> DecryptedPacket (or None to force auth failure).
    The EAX detector sweeps exponents, so the mock must be keyed on the packet
    rather than a positional side_effect list.
    """
    with patch("hubblenetwork.cli.ble_mod.scan_single") as scan:
        scan.side_effect = [*pkts, None]
        if decrypted_for is None:
            return CliRunner().invoke(cli, ["ble", "scan", "-t", "1", *args])
        with patch(
            "hubblenetwork.cli.decrypt_eax",
            side_effect=lambda key, pkt, **kw: decrypted_for.get(pkt.eid),
        ):
            return CliRunner().invoke(cli, ["ble", "scan", "-t", "1", *args])


class TestPayloadFormatDefaults:
    def test_json_payload_stays_base64(self):
        """The machine path must not inherit the tabular 'auto' default."""
        res = _scan(["-o", "json"], [_eax()])
        assert res.exit_code == 0
        assert json.loads(res.stdout)[0]["payload"] == "0weRLGa6QBjl"

    def test_tabular_renders_printable_payload_as_text(self):
        res = _scan(
            ["--key", KEY_HEX],
            [_eax()],
            decrypted_for={_eax().eid: _decrypted(payload=b"T=21.4")},
        )
        assert res.exit_code == 0
        assert "T=21.4" in res.stdout
        assert "VD0yMS40" not in res.stdout  # not base64

    def test_tabular_renders_binary_payload_as_hex(self):
        res = _scan([], [_eax()])
        assert res.exit_code == 0
        assert "D307912C66BA4018E5" in res.stdout

    def test_explicit_payload_format_still_wins_on_tabular(self):
        res = _scan(["--payload-format", "base64"], [_eax()])
        assert res.exit_code == 0
        assert "0weRLGa6QBjl" in res.stdout

    def test_auto_is_selectable_explicitly(self):
        res = _scan(["--payload-format", "auto", "-o", "json"], [_eax()])
        assert res.exit_code == 0
        assert json.loads(res.stdout)[0]["payload"] == "D307912C66BA4018E5"


class TestStreamDiscipline:
    def test_chrome_goes_to_stderr_not_stdout(self):
        res = _scan([], [_eax(), _eax(1)])
        assert res.exit_code == 0
        assert "Scanning for Hubble devices" in res.stderr
        assert "Scanning for Hubble devices" not in res.stdout
        assert "2 packets" in res.stderr
        assert "2 packets" not in res.stdout

    def test_stdout_holds_only_table_rows(self):
        res = _scan([], [_eax()])
        body = [ln for ln in res.stdout.splitlines() if ln.strip()]
        # header, rule, one row, closing rule
        assert len(body) == 4
        assert "TIME" in body[0]

    def test_json_stdout_is_parseable_with_no_prose(self):
        res = _scan(["-o", "json"], [_eax()])
        assert json.loads(res.stdout)  # would raise if chrome leaked in

    def test_no_ansi_when_not_a_tty(self):
        res = _scan([], [_eax()])
        assert ANSI.search(res.stdout) is None


class TestAlignment:
    @staticmethod
    def _widths(stdout):
        return {len(ANSI.sub("", ln).rstrip()) for ln in stdout.splitlines() if ln.strip()}

    def test_no_row_exceeds_its_rule(self):
        """The old renderer padded but never truncated, so long payloads
        pushed a row wider than the separator above it."""
        res = _scan([], [_v1(nbytes=18)])
        rules = [
            ANSI.sub("", ln) for ln in res.stdout.splitlines() if set(ln.strip()) == {"─"}
        ]
        assert rules, "expected a rule line"
        rule_width = len(rules[0])
        for line in res.stdout.splitlines():
            assert len(ANSI.sub("", line).rstrip()) <= rule_width

    def test_default_ble_table_fits_eighty_columns(self):
        res = _scan(["--key", KEY_HEX, "--show-failed-decryption"],
                    [_eax()], decrypted_for={_eax().eid: _decrypted()})
        assert max(self._widths(res.stdout)) <= 80

    def test_truncated_payload_reports_real_byte_count(self):
        cell = _fit("A" * 40, 10, nbytes=20)
        assert len(cell) == 10
        assert cell == "AAAAAA+20B"

    def test_fit_pads_short_values(self):
        assert _fit("ab", 5) == "ab   "


class TestSignalBar:
    def test_bar_is_fixed_width(self):
        assert all(len(_signal_bar(r)) == 5 for r in (-30, -62, -100, -140, None))

    def test_bar_length_tracks_signal_strength(self):
        strong = _signal_bar(-45).rstrip()
        weak = _signal_bar(-90).rstrip()
        assert len(strong) > len(weak)

    def test_floor_and_ceiling_clamp(self):
        assert _signal_bar(-10).rstrip() == "█" * 5
        assert _signal_bar(-120).rstrip() == ""


class TestDebugColumns:
    def test_default_omits_forensic_columns(self):
        res = _scan([], [_eax()])
        for header in ("EPOCH", "TAG", "SALT"):
            assert header not in res.stdout

    def test_debug_adds_forensic_columns_and_values(self):
        res = _scan(["--debug"], [_eax()])
        for header in ("EPOCH", "TAG", "SALT"):
            assert header in res.stdout
        assert "7b2ec109" in res.stdout  # auth tag
        assert "4a1f" in res.stdout  # nonce salt, hex like the JSON field
        assert "1753600000" in res.stdout  # epoch

    def test_salt_matches_the_json_representation(self):
        """Tabular used to print the salt in decimal while JSON used hex."""
        tab = _scan(["--debug"], [_eax()])
        js = _scan(["-o", "json"], [_eax()])
        salt = json.loads(js.stdout)[0]["nonce_salt"]
        assert salt in tab.stdout
        assert str(int(salt, 16)) not in tab.stdout


class TestEmptyAndHiddenStates:
    def test_empty_scan_names_a_next_action(self):
        res = _scan([], [])
        assert res.exit_code == 0
        assert "No packets in" in res.stderr
        assert "0xFCA6" in res.stderr
        assert "--timeout" in res.stderr
        assert res.stdout == ""

    def test_empty_json_scan_stays_an_empty_array(self):
        res = _scan(["-o", "json"], [])
        assert res.stdout.strip() == "[]"

    def test_hidden_decrypt_failures_are_declared(self):
        res = _scan(["--key", KEY_HEX], [_eax(), _eax(1)],
                    decrypted_for={_eax().eid: _decrypted()})
        assert "1 packet(s) failed to decrypt and were hidden" in res.stderr
        assert "--show-failed-decryption" in res.stderr

    def test_no_hidden_notice_when_flag_is_set(self):
        res = _scan(["--key", KEY_HEX, "--show-failed-decryption"],
                    [_eax(), _eax(1)], decrypted_for={_eax().eid: _decrypted()})
        assert "were hidden" not in res.stderr

    def test_summary_reports_rssi_range(self):
        res = _scan([], [_eax(0), _eax(2)])
        assert "RSSI -62 to -70 dBm" in res.stderr


class TestDecryptMark:
    def test_marks_appear_for_both_outcomes(self):
        res = _scan(["--key", KEY_HEX, "--show-failed-decryption"],
                    [_eax(), _eax(1)], decrypted_for={_eax().eid: _decrypted()})
        assert "✓" in res.stdout
        assert "✗" in res.stdout

    def test_json_keeps_word_statuses(self):
        """The mark is a human affordance; the machine contract keeps ok/fail."""
        res = _scan(["--key", KEY_HEX, "--show-failed-decryption", "-o", "json"],
                    [_eax(), _eax(1)], decrypted_for={_eax().eid: _decrypted()})
        statuses = [p["decrypt_status"] for p in json.loads(res.stdout)]
        assert statuses == ["ok", "fail"]


class TestHelpDescribesReality:
    @pytest.mark.parametrize(
        "args,needle",
        [
            (["ble", "scan", "--help"], "--debug"),
            (["ble", "scan", "--help"], "auto"),
            (["sat", "scan", "--help"], "auto"),
        ],
    )
    def test_help_mentions_new_surface(self, args, needle):
        res = CliRunner().invoke(cli, args)
        assert res.exit_code == 0
        assert needle in res.stdout


class TestSummaryReconciles:
    def test_tally_sums_to_the_packet_count(self):
        res = _scan(["--key", KEY_HEX, "--show-failed-decryption"],
                    [_eax(0), _eax(1), _eax(2)],
                    decrypted_for={_eax(0).eid: _decrypted(0),
                                   _eax(2).eid: _decrypted(2)})
        # The auto-detect WARN line also contains the word "packets", so anchor
        # on the summary's leading count.
        line = next(
            ln for ln in res.stderr.splitlines() if re.match(r"^\d+ packets", ln)
        )
        total = int(re.search(r"(\d+) packets", line).group(1))
        ok = int(re.search(r"(\d+) decrypted", line).group(1))
        failed = int(re.search(r"(\d+) failed", line).group(1))
        assert ok + failed == total == 3

    def test_no_tally_when_no_key_was_given(self):
        res = _scan([], [_eax()])
        assert "decrypted" not in res.stderr

    def test_rows_carry_no_trailing_padding(self):
        res = _scan([], [_eax()])
        for line in res.stdout.splitlines():
            assert line == line.rstrip(), repr(line)
