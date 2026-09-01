"""Terminal compatibility: glyphs degrade, colour obeys the conventions.

A reviewer cautioned "be careful with fancy terminal escapes, not all terminals
may be compatible". Two separate risks sat behind that:

  - Writing box-drawing or block glyphs to a cp1252/cp437/ascii stdout raises
    UnicodeEncodeError. `ble scan --help` did exactly that, before any scan,
    because the marks were inside a help string.
  - Most of those glyphs are East Asian Width "Ambiguous", so they render
    double-width under a CJK terminal configuration and shear every column.
    That cannot be detected from the encoding, hence --ascii / HUBBLE_ASCII.

Colour is a separate axis: Click implements no NO_COLOR support at any version,
so it lives in `termcaps` and is verified on a pty rather than a pipe (piping
strips ANSI for an unrelated reason and hides whether the flag works).
"""

import os
import pathlib
import pty
import re
import sys
from dataclasses import fields
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hubblenetwork import termcaps
from hubblenetwork.ble import _make_packet
from hubblenetwork.cli import _command_index, cli

ANSI = re.compile(r"\033\[[0-9;]*m")
REPO = pathlib.Path(__file__).resolve().parents[1]

# A version-0 advertisement: version+seq (2) | EID (4) | tag (4) | ciphertext.
_CTR_RAW = bytes([0x01, 0x2C]) + bytes(range(2, 16))


def _scan(args, charset="utf-8"):
    with patch("hubblenetwork.cli.ble_mod.scan_stream") as m:
        m.return_value = [_make_packet(_CTR_RAW, -62)]
        return CliRunner(charset=charset).invoke(cli, ["ble", "scan", "-t", "1", *args])


class _FakeStream:
    def __init__(self, encoding):
        self.encoding = encoding


@pytest.fixture
def streams(monkeypatch):
    """Swap both stdout and stderr encodings for the probe."""
    def apply(encoding):
        monkeypatch.setattr(sys, "stdout", _FakeStream(encoding))
        monkeypatch.setattr(sys, "stderr", _FakeStream(encoding))
    return apply


class TestCapabilityResolution:
    def test_ascii_flag_beats_a_utf8_stream(self, streams):
        streams("utf-8")
        termcaps.set_explicit_ascii(True)
        assert termcaps.ascii_mode() is True

    def test_no_ascii_flag_beats_a_cp1252_stream(self, streams):
        streams("cp1252")
        termcaps.set_explicit_ascii(False)
        assert termcaps.ascii_mode() is False

    @pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on"])
    def test_hubble_ascii_truthy(self, raw, streams, monkeypatch):
        streams("utf-8")
        monkeypatch.setenv("HUBBLE_ASCII", raw)
        assert termcaps.ascii_mode() is True

    @pytest.mark.parametrize("raw", ["0", "false", "no", "off"])
    def test_hubble_ascii_falsey_overrides_the_probe(self, raw, streams, monkeypatch):
        streams("cp1252")
        monkeypatch.setenv("HUBBLE_ASCII", raw)
        assert termcaps.ascii_mode() is False

    def test_empty_hubble_ascii_falls_through(self, streams, monkeypatch):
        streams("utf-8")
        monkeypatch.setenv("HUBBLE_ASCII", "")
        assert termcaps.ascii_mode() is False

    @pytest.mark.parametrize("enc", ["cp1252", "cp437", "ascii", "latin-1"])
    def test_encodings_that_cannot_hold_the_glyphs_select_ascii(self, enc, streams):
        streams(enc)
        assert termcaps.ascii_mode() is True

    def test_latin1_is_rejected_because_of_the_rule_glyph(self, streams):
        """latin-1 encodes the middot but not the box-drawing rule.

        Proves the probe is derived from the glyph set rather than a denylist of
        codec names, which would have waved latin-1 through.
        """
        assert "\u00b7".encode("latin-1")
        with pytest.raises(UnicodeEncodeError):
            "\u2500".encode("latin-1")
        streams("latin-1")
        assert termcaps.ascii_mode() is True

    def test_utf8_selects_unicode(self, streams):
        streams("utf-8")
        assert termcaps.ascii_mode() is False

    def test_missing_encoding_selects_ascii(self, streams):
        streams(None)
        assert termcaps.ascii_mode() is True

    def test_unknown_codec_selects_ascii(self, streams):
        streams("not-a-real-codec")
        assert termcaps.ascii_mode() is True

    def test_either_stream_failing_selects_ascii(self, monkeypatch):
        monkeypatch.setattr(sys, "stdout", _FakeStream("utf-8"))
        monkeypatch.setattr(sys, "stderr", _FakeStream("cp1252"))
        assert termcaps.ascii_mode() is True


class TestGlyphTableShape:
    def test_both_variants_cover_the_same_roles(self):
        u = {f.name for f in fields(termcaps.UNICODE)}
        a = {f.name for f in fields(termcaps.ASCII)}
        assert u == a

    @pytest.mark.parametrize("role", [f.name for f in fields(termcaps.Glyphs)])
    def test_substitute_has_the_same_length(self, role):
        """The tables do their arithmetic with len(), so this must hold."""
        assert len(getattr(termcaps.ASCII, role)) == len(getattr(termcaps.UNICODE, role))

    @pytest.mark.parametrize("role", [f.name for f in fields(termcaps.Glyphs)])
    def test_ascii_variant_is_actually_ascii(self, role):
        getattr(termcaps.ASCII, role).encode("ascii")

    @pytest.mark.parametrize("variant", [termcaps.UNICODE, termcaps.ASCII])
    def test_bar_partials_has_exactly_seven_entries(self, variant):
        """Indexed by eighths as bar_partials[rem - 1] for rem in 1..7."""
        assert len(variant.bar_partials) == 7

    def test_sep_pad_is_five_cells_in_both_modes(self):
        termcaps.set_explicit_ascii(False)
        assert len(termcaps.sep_pad()) == 5
        termcaps.set_explicit_ascii(True)
        assert len(termcaps.sep_pad()) == 5


HELP_PATHS = sorted(_command_index(cli)) + ["ble", "org", "ready", "sat", "metrics"]


class TestHelpNeverCrashes:
    """`ble scan --help` used to raise before printing anything."""

    @pytest.mark.parametrize("path", HELP_PATHS)
    def test_help_renders_on_a_cp1252_stdout(self, path):
        res = CliRunner(charset="cp1252").invoke(cli, path.split() + ["--help"])
        assert res.exit_code == 0, res.output
        assert res.exception is None

    def test_scan_help_no_longer_names_the_marks(self):
        """Naming the glyphs was a lie in one mode and a crash in the other."""
        res = CliRunner().invoke(cli, ["ble", "scan", "--help"])
        assert "ok/fail decrypt mark" in res.stdout
        assert "\u2713" not in res.stdout
        assert "\u2717" not in res.stdout


class TestNoUnicodeEncodeError:
    """A cp1252 runner opens stdout strict, so a leaked glyph raises."""

    def test_ble_scan_table_renders(self):
        res = _scan([], charset="cp1252")
        assert res.exception is None
        assert res.exit_code == 0
        assert "#" in res.stdout
        assert "---" in res.stdout
        assert "\u2500" not in res.stdout
        assert "\u2588" not in res.stdout

    def test_summary_separator_does_not_leak(self):
        """CliRunner's stderr is backslashreplace, so check for the escape."""
        res = _scan([], charset="cp1252")
        assert "\\u00b7" not in res.stderr
        assert "|" in res.stderr

    def test_period_label_renders(self):
        from hubblenetwork.cli import _format_period_exponent

        termcaps.set_explicit_ascii(True)
        assert _format_period_exponent(15) == "~9h"
        termcaps.set_explicit_ascii(False)
        assert _format_period_exponent(15) == "\u22489h"

    def test_docker_message_is_ascii_and_has_no_hyperlink_escape(self):
        from hubblenetwork.cli import _docker_err_msg

        msg = _docker_err_msg()
        msg.encode("ascii")
        assert "\x1b" not in msg
        assert "]8;;" not in msg

    def test_sat_strings_are_ascii(self):
        import inspect

        from hubblenetwork import sat

        src = inspect.getsource(sat)
        src.encode("ascii")


class TestBothModesRenderTheSameShape:
    @staticmethod
    def _widths(res):
        return [len(ANSI.sub("", ln).rstrip()) for ln in res.stdout.splitlines()]

    def test_row_and_rule_widths_are_identical_across_modes(self):
        """The alignment invariant, without hard-coding a number that rots."""
        assert self._widths(_scan(["--no-ascii"])) == self._widths(_scan(["--ascii"]))

    @pytest.mark.parametrize("rssi", [-30, -45, -62, -90, -100, -140, None])
    @pytest.mark.parametrize("ascii_mode", [True, False])
    def test_signal_bar_is_always_five_cells(self, rssi, ascii_mode):
        from hubblenetwork.cli import _signal_bar

        termcaps.set_explicit_ascii(ascii_mode)
        assert len(_signal_bar(rssi)) == 5

    @pytest.mark.parametrize("ascii_mode", [True, False])
    def test_bar_length_is_monotonic(self, ascii_mode):
        from hubblenetwork.cli import _signal_bar

        termcaps.set_explicit_ascii(ascii_mode)
        lengths = [len(_signal_bar(r).rstrip()) for r in range(-100, -39)]
        assert lengths == sorted(lengths)

    def test_no_row_exceeds_its_rule_in_ascii_mode(self):
        res = _scan(["--ascii"])
        rules = [
            ANSI.sub("", ln)
            for ln in res.stdout.splitlines()
            if set(ln.strip()) == {"-"}
        ]
        assert rules
        for line in res.stdout.splitlines():
            assert len(ANSI.sub("", line).rstrip()) <= len(rules[0])


class TestMachineOutputIsUnaffected:
    def test_json_bytes_are_identical_across_modes(self):
        a = _scan(["-o", "json", "--no-ascii"]).stdout
        b = _scan(["-o", "json", "--ascii"]).stdout
        assert a == b

    def test_json_is_ascii_by_construction(self):
        """No json.dumps call may pass ensure_ascii=False.

        That default is what makes every JSON path emit \\uXXXX escapes rather
        than raw glyphs, so the machine contract needs no fallback machinery.
        """
        offenders = [
            path.name
            for path in (REPO / "src" / "hubblenetwork").glob("*.py")
            if re.search(r"ensure_ascii\s*=\s*False", path.read_text())
        ]
        assert not offenders, offenders

    def test_tabulate_grid_format_stays_ascii(self):
        """fancy_grid and friends are Unicode box-drawing."""
        src = (REPO / "src" / "hubblenetwork" / "cli.py").read_text()
        assert "fancy_grid" not in src
        assert "rounded_grid" not in src
        assert 'tablefmt="grid"' in src


class TestColorControl:
    """Measured on a pty: piping strips ANSI for an unrelated reason."""

    @staticmethod
    def _escapes(env_extra, args):
        script = REPO / "tests" / "_color_probe.py"
        script.write_text(
            "import sys\n"
            "from unittest.mock import patch\n"
            "from hubblenetwork.cli import main\n"
            "from hubblenetwork.ble import _make_packet\n"
            "raw = bytes([0x01, 0x2C]) + bytes(range(2, 16))\n"
            "with patch('hubblenetwork.cli.ble_mod.scan_stream') as m:\n"
            "    m.return_value = [_make_packet(raw, -62)]\n"
            "    sys.exit(main(sys.argv[1:]))\n"
        )
        try:
            env = dict(os.environ, **env_extra)
            env.pop("NO_COLOR", None)
            env.update(env_extra)
            chunks = []
            pid, fd = pty.fork()
            if pid == 0:
                os.execve(sys.executable, [sys.executable, str(script), *args], env)
            try:
                while True:
                    data = os.read(fd, 4096)
                    if not data:
                        break
                    chunks.append(data)
            except OSError:
                pass
            os.waitpid(pid, 0)
            return b"".join(chunks).count(b"\x1b")
        finally:
            script.unlink(missing_ok=True)

    ARGS = ["ble", "scan", "-t", "1"]

    def test_a_tty_gets_colour_by_default(self):
        assert self._escapes({}, self.ARGS) > 0

    def test_no_color_env_strips_it(self):
        assert self._escapes({"NO_COLOR": "1"}, self.ARGS) == 0

    def test_empty_no_color_is_not_a_signal(self):
        """no-color.org: any non-empty value disables; empty is not a signal."""
        assert self._escapes({"NO_COLOR": ""}, self.ARGS) > 0

    def test_no_color_flag_strips_it(self):
        assert self._escapes({}, [*self.ARGS, "--no-color"]) == 0

    def test_no_color_flag_works_before_the_subcommand(self):
        assert self._escapes({}, ["--no-color", *self.ARGS]) == 0

    def test_ascii_mode_still_gets_colour(self):
        """The two axes are independent."""
        assert self._escapes({}, [*self.ARGS, "--ascii"]) > 0


class TestFlagsReachEveryCommand:
    @pytest.mark.parametrize("path", sorted(_command_index(cli)))
    def test_every_command_accepts_ascii(self, path):
        res = CliRunner().invoke(cli, path.split() + ["--ascii", "--help"])
        assert res.exit_code == 0, res.output

    @pytest.mark.parametrize("path", sorted(_command_index(cli)))
    def test_every_command_accepts_no_color(self, path):
        res = CliRunner().invoke(cli, path.split() + ["--no-color", "--help"])
        assert res.exit_code == 0, res.output

    def test_both_are_documented_in_root_help(self):
        out = CliRunner().invoke(cli, ["--help"]).stdout
        assert "--ascii" in out
        assert "--no-color" in out

    def test_they_stay_hidden_on_leaf_help(self):
        """26 help screens should not each grow two rendering flags."""
        out = CliRunner().invoke(cli, ["ble", "scan", "--help"]).stdout
        assert "--no-ascii" not in out

    def test_unknown_option_list_excludes_the_hidden_flags(self):
        res = CliRunner().invoke(cli, ["org", "list-devices", "--nope"])
        assert "--ascii" not in res.output
        assert "--no-color" not in res.output


class TestSourceStaysAscii:
    def test_only_termcaps_may_hold_non_ascii(self):
        """Turns "remember not to inline a glyph" into a failing test.

        ruff cannot do this: RUF001-003 flag only ambiguous/confusable
        characters, so box-drawing and block glyphs sail through.
        """
        offenders = []
        for path in sorted((REPO / "src" / "hubblenetwork").glob("*.py")):
            if path.name == "termcaps.py":
                continue
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                for ch in line:
                    if ord(ch) > 126:
                        offenders.append(f"{path.name}:{lineno}: U+{ord(ch):04X} {ch!r}")
        assert not offenders, "non-ASCII outside termcaps.py:\n" + "\n".join(offenders)
