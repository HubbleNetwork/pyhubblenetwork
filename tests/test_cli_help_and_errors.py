"""No dead ends: every failure path names something the user can run next.

Also locks the help contract: the command column is generated from the Click
tree, so a new command cannot silently go undocumented.
"""

import re

import click
import pytest
from click.testing import CliRunner

from hubblenetwork.cli import (
    HubbleGroup,
    _command_index,
    _invocation,
    _suggest_commands,
    cli,
    main,
)

ANSI = re.compile(r"\033\[[0-9;]*m")


def _run(args, env=None):
    return CliRunner().invoke(cli, args, env=env)


def _plain(res):
    return ANSI.sub("", (res.stdout or "") + (res.stderr or ""))


def _main_output(args, capsys, env=None, monkeypatch=None):
    """Drive main() rather than the group, since main() formats the errors."""
    if monkeypatch is not None:
        for k in ("HUBBLE_ORG_ID", "HUBBLE_API_TOKEN"):
            monkeypatch.delenv(k, raising=False)
        for k, v in (env or {}).items():
            monkeypatch.setenv(k, v)
    code = main(args)
    captured = capsys.readouterr()
    return code, ANSI.sub("", captured.out + captured.err)


LEAVES = sorted(_command_index(cli))


class TestEveryCommandDescribesItself:
    @pytest.mark.parametrize("path", LEAVES)
    def test_has_a_short_help(self, path):
        _, cmd = _command_index(cli)[path]
        assert cmd.short_help, f"{path} has no short_help"

    @pytest.mark.parametrize("path", LEAVES)
    def test_short_help_fits_the_column(self, path):
        _, cmd = _command_index(cli)[path]
        assert len(cmd.get_short_help_str(60)) <= 44, f"{path} description too long"

    @pytest.mark.parametrize("path", LEAVES)
    def test_appears_in_root_help(self, path):
        out = _plain(_run(["--help"]))
        p, cmd = _command_index(cli)[path]
        assert _invocation(p, cmd) in out, f"{path} missing from --help"

    def test_root_help_lists_every_command(self):
        out = _plain(_run(["--help"]))
        assert len(LEAVES) == 26  # guard: update the help sections if this grows
        for path in LEAVES:
            p, cmd = _command_index(cli)[path]
            assert _invocation(p, cmd) in out

    def test_root_help_has_a_start_here_section(self):
        out = _plain(_run(["--help"]))
        assert "Start here" in out
        assert "hubblenetwork org get-packets --help" in out

    def test_root_help_fits_eighty_columns(self):
        out = _plain(_run(["--help"], env={"COLUMNS": "80"}))
        for line in out.splitlines():
            assert len(line.rstrip()) <= 80, repr(line)

    @pytest.mark.parametrize("group", ["ble", "ready", "org", "sat", "metrics"])
    def test_group_help_shows_full_invocations(self, group):
        out = _plain(_run([group, "--help"]))
        assert f"{group} " in out
        for path in LEAVES:
            if path.startswith(group + " "):
                p, cmd = _command_index(cli)[path]
                assert _invocation(p, cmd) in out

    def test_required_arguments_appear_as_metavars(self):
        out = _plain(_run(["--help"]))
        assert "org get-packets <id>" in out
        assert "org set-device-name <id> <name>" in out
        assert "sat record <seconds>" in out


class TestUnknownCommandSuggestions:
    def test_leaf_name_typed_at_the_root_points_to_its_group(self, capsys):
        code, out = _main_output(["list-devices"], capsys)
        assert code == 2
        assert "hubblenetwork org list-devices" in out

    def test_typo_resolves_to_the_real_command(self, capsys):
        code, out = _main_output(["list-device"], capsys)
        assert code == 2
        assert "hubblenetwork org list-devices" in out

    def test_ambiguous_name_lists_every_home(self, capsys):
        code, out = _main_output(["scan"], capsys)
        assert code == 2
        assert "exists in more than one group" in out
        for grp in ("ble", "ready", "sat"):
            assert f"hubblenetwork {grp} scan" in out

    def test_unrelated_name_still_points_at_help(self, capsys):
        code, out = _main_output(["frobnicate"], capsys)
        assert code == 2
        assert "--help" in out

    def test_wrong_group_still_finds_the_right_one(self, capsys):
        code, out = _main_output(["ble", "list-devices"], capsys)
        assert code == 2
        assert "hubblenetwork org list-devices" in out

    @pytest.mark.parametrize(
        "typed,expected",
        [
            ("get-packets", "org get-packets"),
            ("register-device", "org register-device"),
            ("provision", "ready provision"),
            ("mock-scan", "sat mock-scan"),
            ("detect", "ble detect"),
            ("devices", "metrics devices"),
        ],
    )
    def test_every_leaf_name_is_findable_from_the_root(self, typed, expected):
        paths, kind = _suggest_commands(typed)
        assert expected in paths, (typed, paths)

    def test_suggestions_are_capped(self):
        paths, _ = _suggest_commands("read")
        assert len(paths) <= 3


class TestUnknownOption:
    def test_close_spelling_is_suggested_by_click(self, capsys):
        code, out = _main_output(["ble", "scan", "--timout", "5"], capsys)
        assert code == 2
        assert "--timeout" in out

    def test_unrelated_option_lists_what_is_accepted(self, capsys):
        code, out = _main_output(["org", "list-devices", "--json"], capsys)
        assert code == 2
        assert "This command accepts:" in out
        assert "--format" in out
        assert "--limit" in out


class TestMissingArguments:
    def test_device_id_says_how_to_find_one(self, capsys):
        code, out = _main_output(["org", "get-packets"], capsys)
        assert code == 2
        assert "Missing argument '<id>'" in out
        assert "hubblenetwork org list-devices" in out

    def test_duration_gives_units_and_an_example(self, capsys):
        code, out = _main_output(["sat", "record"], capsys)
        assert code == 2
        assert "Missing argument '<seconds>'" in out
        assert "hubblenetwork sat record 10" in out

    def test_usage_line_is_preserved(self, capsys):
        code, out = _main_output(["org", "delete-device"], capsys)
        assert "Usage: hubblenetwork org delete-device" in out

    def test_name_argument_gives_an_example(self, capsys):
        code, out = _main_output(["org", "set-device-name", "abc"], capsys)
        assert code == 2
        assert "hubblenetwork org set-device-name" in out


class TestCredentialErrors:
    def test_unset_credentials_name_both_variables(self, capsys, monkeypatch):
        code, out = _main_output(["org", "list-devices"], capsys, monkeypatch=monkeypatch)
        assert code == 1
        assert "HUBBLE_ORG_ID" in out
        assert "HUBBLE_API_TOKEN" in out
        assert "export HUBBLE_ORG_ID=" in out
        assert "--org-id" in out
        assert "validate-credentials" in out

    def test_rejected_credentials_get_different_advice(self, capsys, monkeypatch):
        code, out = _main_output(
            ["org", "--org-id", "bogus", "--token", "bogus", "info"],
            capsys, monkeypatch=monkeypatch,
        )
        assert code == 1
        assert "rejected" in out
        assert "export HUBBLE_ORG_ID=" not in out

    def test_validate_credentials_exits_nonzero_on_failure(self, capsys, monkeypatch):
        """Exit 0 on invalid credentials made this undetectable in scripts."""
        code, out = _main_output(["validate-credentials"], capsys, monkeypatch=monkeypatch)
        assert code == 1
        assert "No valid Hubble credentials" in out

    def test_ingest_without_credentials_shows_its_own_invocation(self, capsys, monkeypatch):
        """--ingest used to be env-var only, and pointed at the org command."""
        code, out = _main_output(
            ["ble", "scan", "--ingest", "--key", "00" * 16, "-t", "1"],
            capsys, monkeypatch=monkeypatch,
        )
        assert code == 1
        assert "HUBBLE_ORG_ID" in out
        assert "export HUBBLE_ORG_ID=" in out
        assert "ble scan --ingest" in out
        assert "org --org-id <id> --token <token> list-devices" not in out

    def test_ingest_accepts_credential_flags(self):
        res = _run(["ble", "scan", "--help"])
        assert "--org-id" in res.stdout
        assert "--token" in res.stdout


class TestHelpNeedsNoCredentials:
    @pytest.mark.parametrize(
        "args",
        [
            ["org", "list-devices", "--help"],
            ["org", "get-packets", "--help"],
            ["metrics", "devices", "--help"],
            ["metrics", "--help"],
            ["org", "--help"],
        ],
    )
    def test_help_is_reachable(self, args, monkeypatch):
        monkeypatch.delenv("HUBBLE_ORG_ID", raising=False)
        monkeypatch.delenv("HUBBLE_API_TOKEN", raising=False)
        res = _run(args)
        assert res.exit_code == 0, _plain(res)
        assert "Usage:" in res.stdout


class TestBareGroup:
    @pytest.mark.parametrize("group", ["ble", "ready", "org", "sat", "metrics"])
    def test_bare_group_shows_its_commands_not_an_error_prefix(
        self, group, capsys, monkeypatch
    ):
        code, out = _main_output([group], capsys, monkeypatch=monkeypatch)
        assert code == 2
        assert "Error: Usage:" not in out
        assert "Commands" in out


class TestGroupsUseTheCustomClass:
    def test_every_group_is_a_hubble_group(self):
        def walk(cmd):
            if isinstance(cmd, click.Group):
                assert isinstance(cmd, HubbleGroup), cmd.name
                for sub in cmd.commands.values():
                    walk(sub)
        walk(cli)


class TestReadmeStaysTrue:
    """Stale docs teach the old interface with the new one's confidence."""

    #: Every markdown file that documents CLI invocations. The plugin skill docs
    #: had drifted badly (documenting --pool-size and `provision --format json`,
    #: neither of which exist) precisely because nothing checked them.
    DOC_GLOBS = ("README.md", "plugins/**/*.md")

    @classmethod
    def _doc_files(cls):
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1]
        files = []
        for pattern in cls.DOC_GLOBS:
            files.extend(sorted(root.glob(pattern)))
        return files

    @classmethod
    def _commands_in(cls, path):
        """Every `hubblenetwork ...` invocation inside a fenced block.

        Tracked line by line rather than with a regex: an optional language tag
        makes a closing fence indistinguishable from an opening one, which
        silently captures the prose between blocks instead of the blocks.
        """
        import shlex

        runnable = {"bash", "sh", "shell", "console"}
        found = []
        lang = None
        in_fence = False
        for line in path.read_text().splitlines():
            if line.startswith("```"):
                if in_fence:
                    in_fence, lang = False, None
                else:
                    in_fence = True
                    lang = line[3:].strip().lower()
                continue
            # Only fences tagged as a shell hold runnable examples. A bare fence
            # is illustrative output, e.g. the README's "wrong command" demo,
            # which is supposed to fail.
            if not in_fence or lang not in runnable:
                continue
            line = line.split("#")[0].strip().rstrip("\\").strip()
            line = line.removeprefix("$ ").strip()
            if not line.startswith("hubblenetwork "):
                continue
            # Skip shell plumbing, which is not a single argv. Careful not to
            # catch the ">" inside placeholders like <id>.
            if any(tok in line for tok in ("$(", "`", " | ", " && ", " > ", " >> ", "2>")):
                continue
            try:
                found.append(shlex.split(line)[1:])
            except ValueError:
                continue
        return found

    @classmethod
    def _readme_commands(cls):
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[1]
        return cls._commands_in(root / "README.md")

    def test_readme_has_command_examples(self):
        assert len(self._readme_commands()) >= 20

    def test_every_readme_command_resolves(self):
        """Asking for --help proves the path and every flag exist."""
        broken = []
        for args in self._readme_commands():
            res = _run(args + ["--help"])
            out = _plain(res)
            if "No such command" in out or "No such option" in out:
                broken.append((" ".join(args), out.strip().splitlines()[-1]))
        assert not broken, broken

    def test_every_documented_command_resolves_in_every_doc(self):
        """Docs that name a flag the CLI does not accept teach the wrong thing."""
        broken = []
        for path in self._doc_files():
            for args in self._commands_in(path):
                # Strip angle-bracket and UPPER placeholders' values, keeping flags.
                res = _run(args + ["--help"])
                out = _plain(res)
                for marker in ("No such command", "No such option"):
                    if marker in out:
                        bad = next(l for l in out.splitlines() if marker in l)
                        broken.append(f"{path.name}: {' '.join(args)}\n      {bad.strip()}")
        assert not broken, "docs reference things the CLI does not have:\n  " + "\n  ".join(
            broken
        )

    def test_readme_import_block_matches_the_package(self):
        import pathlib
        import re

        import hubblenetwork

        text = pathlib.Path(__file__).resolve().parents[1].joinpath("README.md").read_text()
        block = re.search(r"from hubblenetwork import \(\n(.*?)\)", text, re.S)
        assert block, "README lost its import example"
        names = [
            n.strip().rstrip(",")
            for n in block.group(1).replace("\n", " ").split(",")
            if n.strip()
        ]
        missing = [n for n in names if not hasattr(hubblenetwork, n)]
        assert not missing, missing
