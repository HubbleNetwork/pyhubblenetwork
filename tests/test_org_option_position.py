"""Tests that org-level --org-id/-o and --token/-t can appear anywhere.

Click normally requires group-level options to precede the subcommand name.
The org group uses a custom Group class that hoists the credential options
(and their values) out of the argument list wherever the user placed them, so
e.g. `org register-device -e ... -o ORG -t TOKEN` works.
"""
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from hubblenetwork.org import Organization
from hubblenetwork.cli import cli


def _run(args):
    runner = CliRunner()
    with patch("hubblenetwork.cli.Organization") as mock_org_cls:
        mock_org_cls.return_value = MagicMock(spec=Organization)
        result = runner.invoke(cli, args)
    return result, mock_org_cls


class TestCredentialOptionPositioning:
    def test_credentials_after_subcommand(self):
        """The motivating example: -o/-t trail the subcommand and its options."""
        result, mock_org_cls = _run(
            ["org", "register-device", "-e", "AES-128-EAX",
             "-c", "DEVICE_UPTIME", "-o", "MY_ORG_ID", "-t", "MY_TOKEN"]
        )
        assert result.exit_code == 0, result.output
        mock_org_cls.assert_called_once_with(org_id="MY_ORG_ID", api_token="MY_TOKEN")

    def test_credentials_before_subcommand_still_works(self):
        """Backward compatibility: the old position must still parse."""
        result, mock_org_cls = _run(
            ["org", "-o", "MY_ORG_ID", "-t", "MY_TOKEN",
             "register-device", "-e", "AES-128-EAX", "-c", "DEVICE_UPTIME"]
        )
        assert result.exit_code == 0, result.output
        mock_org_cls.assert_called_once_with(org_id="MY_ORG_ID", api_token="MY_TOKEN")

    def test_credentials_interspersed(self):
        """Credentials split around the subcommand and its options."""
        result, mock_org_cls = _run(
            ["org", "-o", "MY_ORG_ID", "register-device",
             "-e", "AES-128-EAX", "-t", "MY_TOKEN"]
        )
        assert result.exit_code == 0, result.output
        mock_org_cls.assert_called_once_with(org_id="MY_ORG_ID", api_token="MY_TOKEN")

    def test_long_form_with_equals_after_subcommand(self):
        result, mock_org_cls = _run(
            ["org", "register-device", "--org-id=MY_ORG_ID", "--token=MY_TOKEN"]
        )
        assert result.exit_code == 0, result.output
        mock_org_cls.assert_called_once_with(org_id="MY_ORG_ID", api_token="MY_TOKEN")

    def test_long_form_space_separated_after_subcommand(self):
        result, mock_org_cls = _run(
            ["org", "list-devices", "--org-id", "MY_ORG_ID", "--token", "MY_TOKEN"]
        )
        assert result.exit_code == 0, result.output
        mock_org_cls.assert_called_once_with(org_id="MY_ORG_ID", api_token="MY_TOKEN")


class TestGetPacketsFormatRebind:
    """get-packets used to use -o for output format; -o now means org-id."""

    def test_dash_o_is_org_id_on_get_packets(self):
        result, mock_org_cls = _run(
            ["org", "get-packets", "dev-abc", "-o", "MY_ORG_ID", "-t", "MY_TOKEN"]
        )
        assert result.exit_code == 0, result.output
        mock_org_cls.assert_called_once_with(org_id="MY_ORG_ID", api_token="MY_TOKEN")

    def test_dash_f_controls_format(self):
        runner = CliRunner()
        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            mock_org.retrieve_packets.return_value = []
            result = runner.invoke(
                cli,
                ["org", "-o", "MY_ORG_ID", "-t", "MY_TOKEN",
                 "get-packets", "dev-abc", "-f", "json"],
            )
        assert result.exit_code == 0, result.output
        assert result.output.strip() == "[]"

    def test_org_id_and_format_together(self):
        """-o as org-id and -f as format coexist on get-packets."""
        runner = CliRunner()
        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            mock_org.retrieve_packets.return_value = []
            result = runner.invoke(
                cli,
                ["org", "get-packets", "dev-abc",
                 "-o", "MY_ORG_ID", "-t", "MY_TOKEN", "-f", "json"],
            )
        assert result.exit_code == 0, result.output
        assert result.output.strip() == "[]"
        mock_org_cls.assert_called_once_with(org_id="MY_ORG_ID", api_token="MY_TOKEN")
