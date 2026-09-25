"""`ble decode`: scan, decrypt in the cloud, stream rows (BLE and cloud mocked)."""
from __future__ import annotations

import json
import re
import time
from dataclasses import replace
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hubblenetwork import InvalidCredentialsError
from hubblenetwork.cli import cli
from hubblenetwork.errors import BackendError, PermissionDeniedError
from hubblenetwork.packets import DecryptedPacket, UnencryptedPacket
from tests.fake_packets import as_packet, make_ctr, make_eax

ANSI = re.compile(r"\033\[[0-9;]*m")
KEY = bytes(range(32))
EAX_KEY = bytes(range(16))
DEVICE_ID = "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"
CREDS = ["--org-id", "o", "--token", "t"]


def _pkt(i: int, rssi: int = -60):
    return as_packet(make_ctr(KEY, b"p", seq_no=i), rssi=rssi)


def _decoded(pkt, name="dev-a", payload=b"hello"):
    return DecryptedPacket(
        timestamp=pkt.timestamp, device_id=DEVICE_ID, device_name=name,
        location=pkt.location, tags={"t": "1"}, payload=payload, rssi=pkt.rssi,
        counter=20000, sequence=pkt.seq_no, protocol_version=0, eid=pkt.eid,
        auth_tag=pkt.auth_tag,
    )


def _run(pkts, args=(), decode=None, log=None):
    """Feed `pkts` through scan_single, then Ctrl+C."""
    feed = list(pkts) + [KeyboardInterrupt()]

    def scan_single(timeout=None):
        if log is not None:
            log.append("scan")
        item = feed.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def default_decode(ps):
        if log is not None:
            log.append(("decode", len(ps)))
        return [_decoded(p) for p in ps]

    with patch("hubblenetwork.cli.Organization") as org_cls, \
         patch("hubblenetwork.cli.ble_mod") as ble:
        ble.scan_single.side_effect = scan_single
        org = org_cls.return_value
        org.decode_packets.side_effect = decode or default_decode
        res = CliRunner().invoke(cli, ["ble", "decode", *CREDS, *args])
    return res, org


class TestOutputContract:
    def test_rows_on_stdout_chrome_on_stderr(self):
        res, _ = _run([_pkt(1), _pkt(2)])
        assert res.exit_code == 0, res.output
        out, err = ANSI.sub("", res.stdout), ANSI.sub("", res.stderr)
        assert "DEVICE" in out and "PAYLOAD" in out
        assert out.count("dev-a") == 2
        assert "hello" in out
        assert "Scanning" not in out and "packets" not in out.split("PAYLOAD")[1]
        assert "Scanning and decrypting" in err
        assert "2 packets" in err
        assert "2 decrypted, 0 failed" in err

    def test_rows_fit_eighty_columns_with_the_gutter(self):
        res, _ = _run([_pkt(1)], args=["--show-failed"])
        for line in ANSI.sub("", res.stdout).splitlines():
            assert len(line) <= 80, repr(line)

    def test_long_payload_truncates_with_byte_count(self):
        def decode(ps):
            return [_decoded(p, payload=b"A" * 40) for p in ps]

        res, _ = _run([_pkt(1)], decode=decode)
        assert "+40B" in ANSI.sub("", res.stdout)

    def test_json_is_a_parseable_array_and_quiet(self):
        res, _ = _run([_pkt(1), _pkt(2)], args=["-o", "json"])
        assert res.exit_code == 0, res.output
        rows = json.loads(res.stdout)
        assert [r["device_id"] for r in rows] == [DEVICE_ID, DEVICE_ID]
        assert rows[0]["device_name"] == "dev-a"
        assert rows[0]["payload"] == "aGVsbG8="  # base64 by default in JSON
        assert rows[0]["counter"] == 20000
        assert "decrypt_status" not in rows[0]
        assert res.stderr == ""

    def test_json_empty_scan(self):
        res, _ = _run([], args=["-o", "json"])
        assert json.loads(res.stdout) == []

    def test_undecrypted_hidden_by_default(self):
        res, _ = _run([_pkt(1), _pkt(2)], decode=lambda ps: [None] * len(ps))
        out, err = ANSI.sub("", res.stdout), ANSI.sub("", res.stderr)
        assert "DEVICE" not in out
        assert "Heard 2, none decrypted" in err
        assert "--show-failed" in err

    def test_hidden_failures_dont_read_as_zero_failed(self):
        """The tally once said "0 failed" right above "1 ... were hidden"."""
        def decode(ps):
            return [None if p.seq_no == 2 else _decoded(p) for p in ps]

        res, _ = _run([_pkt(1), _pkt(2), _pkt(3)], decode=decode)
        err = ANSI.sub("", res.stderr)
        assert "2 packets" in err
        assert "2 decrypted" in err
        assert "failed," not in err and "0 failed" not in err
        assert "1 packet(s) failed to decrypt and were hidden" in err

    def test_show_failed_marks_rows(self):
        def decode(ps):
            return [None if p.seq_no == 2 else _decoded(p) for p in ps]

        res, _ = _run([_pkt(1), _pkt(2)], args=["--show-failed"], decode=decode)
        out, err = ANSI.sub("", res.stdout), ANSI.sub("", res.stderr)
        rows = [line for line in out.splitlines() if line.strip()[:1] in ("✓", "✗", "+", "x")]
        assert len(rows) == 2
        assert "1 decrypted, 1 failed" in err

    def test_json_show_failed_carries_status(self):
        def decode(ps):
            return [None] * len(ps)

        res, _ = _run([_pkt(1)], args=["-o", "json", "--show-failed"], decode=decode)
        (row,) = json.loads(res.stdout)
        assert row["decrypt_status"] == "fail"
        assert row["device_id"] is None

    def test_json_rows_share_one_schema(self):
        """Failed and decoded rows use the same key names, so one parser fits both."""
        def decode(ps):
            return [None if p.seq_no == 2 else _decoded(p) for p in ps]

        res, _ = _run([_pkt(1), _pkt(2)], args=["-o", "json", "--show-failed"],
                      decode=decode)
        ok, fail = json.loads(res.stdout)
        assert ok["decrypt_status"] == "ok" and fail["decrypt_status"] == "fail"
        assert set(ok) == set(fail)
        assert "seq_no" not in fail
        assert fail["sequence"] == 2
        assert fail["counter"] is None
        assert fail["device_id"] is None and fail["device_name"] is None

    def test_json_failed_eax_row_has_null_sequence(self):
        eax = as_packet(make_eax(EAX_KEY, b"e", index=1, period_exponent=0))
        res, _ = _run([eax], args=["-o", "json", "--show-failed"],
                      decode=lambda ps: [None] * len(ps))
        (row,) = json.loads(res.stdout)
        assert row["sequence"] is None and row["device_id"] is None
        assert "seq_no" not in row

    def test_ble_scan_json_keeps_seq_no(self):
        """decode got its own mapping; ble scan's byte-stable JSON is untouched."""
        from hubblenetwork.cli import _packet_to_dict

        assert "seq_no" in _packet_to_dict(_pkt(3))
        assert "sequence" not in _packet_to_dict(_pkt(3))


class TestFailedRows:
    def _failed_row(self, pkt, args=()):
        res, _ = _run([pkt], args=["--show-failed", *args],
                      decode=lambda ps: [None] * len(ps))
        assert res.exit_code == 0, res.output
        out = ANSI.sub("", res.stdout)
        (row,) = [ln for ln in out.splitlines() if ln.strip()[:1] in ("✗", "x")]
        return row

    def test_device_cell_names_the_ctr_eid(self):
        pkt = _pkt(1)
        assert f"eid:{pkt.eid:x}" in self._failed_row(pkt)

    def test_device_cell_fits_an_eax_eid(self):
        eax = as_packet(make_eax(EAX_KEY, b"e", index=1, period_exponent=0))
        row = self._failed_row(eax)
        eid_hex = f"{eax.eid:x}"
        assert f"eid:{eid_hex[:11]}>" in row and "+8B" not in row
        assert len(row) <= 80

    @pytest.mark.parametrize("fmt", [None, "auto", "string", "base64"])
    def test_ciphertext_is_always_hex(self, fmt):
        # Printable ciphertext ("wJ"-like) used to render as if it were a payload.
        pkt = as_packet(make_ctr(KEY, b"p", seq_no=1), rssi=-60)
        pkt = replace(pkt, payload=pkt.payload[:10] + b"wJ")
        args = [] if fmt is None else ["--payload-format", fmt]
        row = self._failed_row(pkt, args)
        assert row.rstrip().endswith("774A")
        assert "wJ" not in row


class TestBatching:
    def test_flushes_when_a_batch_fills(self):
        res, org = _run([_pkt(i) for i in range(30)])
        assert res.exit_code == 0, res.output
        sizes = [len(c.args[0]) for c in org.decode_packets.call_args_list]
        assert sizes == [25, 5]

    def test_streams_by_time_not_just_at_the_end(self):
        log = []
        with patch("hubblenetwork.cli._DECODE_FLUSH_S", 0.0):
            res, _ = _run([_pkt(1), _pkt(2), _pkt(3)], log=log)
        assert res.exit_code == 0, res.output
        # Each packet is decoded before the next scan starts.
        assert log[:6] == ["scan", ("decode", 1)] * 3

    def test_repeated_advertisement_decoded_once(self):
        p = _pkt(1)
        res, org = _run([p, p, p])
        # One request; Organization.decode_packets sends identical ones once.
        assert org.decode_packets.call_count == 1
        assert ANSI.sub("", res.stdout).count("dev-a") == 3

    def test_only_encrypted_packets_are_sent(self):
        eax = as_packet(make_eax(EAX_KEY, b"e", index=1, period_exponent=0))
        unenc = UnencryptedPacket(int(time.time()), None, 5, 1, b"x", -50)
        ctr = _pkt(1)
        res, org = _run([unenc, eax, ctr])
        sent = [p for c in org.decode_packets.call_args_list for p in c.args[0]]
        assert sent == [eax, ctr]

    def test_timeout_bounds_the_scan(self):
        with patch("hubblenetwork.cli.Organization") as org_cls, \
             patch("hubblenetwork.cli.ble_mod") as ble:
            ble.scan_single.return_value = None
            org_cls.return_value.decode_packets.return_value = []
            res = CliRunner().invoke(cli, ["ble", "decode", *CREDS, "-t", "0"])
        assert res.exit_code == 0
        assert "No packets" in ANSI.sub("", res.stderr)


class TestErrors:
    # Missing credentials: tests/test_cli_help_and_errors.py covers ble decode.

    def test_rejected_credentials(self):
        with patch("hubblenetwork.cli.Organization",
                   side_effect=InvalidCredentialsError("bad")):
            res = CliRunner().invoke(cli, ["ble", "decode", *CREDS])
        assert res.exit_code == 1
        assert "rejected" in ANSI.sub("", res.output)

    @pytest.mark.parametrize(
        "error,expected",
        [
            (PermissionDeniedError("lacks the 'read-packets' scope"), "read-packets"),
            (BackendError("500: boom"), "500: boom"),
        ],
    )
    def test_backend_error_stops_cleanly(self, error, expected):
        def decode(ps):
            raise error

        res, _ = _run([_pkt(1)], decode=decode)
        assert res.exit_code == 1
        assert expected in ANSI.sub("", res.stderr)
        assert "Traceback" not in res.output
