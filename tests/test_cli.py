"""Tests for cli.py Click commands."""

from __future__ import annotations

import pytest
import json
from unittest.mock import MagicMock, patch
from click.testing import CliRunner

from hubblenetwork.cli import cli, main
from hubblenetwork.cloud import Credentials, Environment
from hubblenetwork.device import Device
from hubblenetwork.packets import EncryptedPacket, DecryptedPacket, Location


@pytest.fixture
def runner():
    """Create a Click CliRunner."""
    return CliRunner()


class TestCliGroup:
    """Tests for main CLI group."""

    def test_help_option(self, runner):
        """Test --help option works."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Hubble SDK CLI" in result.output

    def test_version_option(self, runner):
        """Test --version option works."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        # Should contain either a version number or "dev"
        assert "hubblenetwork" in result.output.lower() or "version" in result.output.lower()


class TestValidateCredentials:
    """Tests for validate-credentials command."""

    def test_valid_credentials(self, runner):
        """Test with valid credentials."""
        mock_env = Environment(name="PROD", url="https://api.hubble.com")

        with patch("hubblenetwork.cli.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env

            result = runner.invoke(
                cli,
                ["validate-credentials", "--org-id", "test-org", "--token", "test-token"],
            )

            assert result.exit_code == 0
            assert "Valid credentials" in result.output
            assert "PROD" in result.output

    def test_invalid_credentials(self, runner):
        """Test with invalid credentials."""
        with patch("hubblenetwork.cli.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = None

            result = runner.invoke(
                cli,
                ["validate-credentials", "--org-id", "bad-org", "--token", "bad-token"],
            )

            assert "Invalid credentials" in result.output


class TestBleCommands:
    """Tests for BLE subcommands."""

    def test_ble_group_help(self, runner):
        """Test ble group help."""
        result = runner.invoke(cli, ["ble", "--help"])
        assert result.exit_code == 0
        assert "BLE utilities" in result.output

    def test_ble_detect_invalid_key(self, runner):
        """Test ble detect with invalid base64 key."""
        result = runner.invoke(
            cli,
            ["ble", "detect", "--key", "not-valid-base64!!!"],
        )
        # Should fail gracefully
        assert "error" in result.output.lower() or "base64" in result.output.lower()

    def test_ble_scan_help(self, runner):
        """Test ble scan help."""
        result = runner.invoke(cli, ["ble", "scan", "--help"])
        assert result.exit_code == 0
        assert "timeout" in result.output.lower()

    def test_ble_scan_with_invalid_key(self, runner):
        """Test ble scan with invalid base64 key exits with error."""
        with patch("hubblenetwork.cli.ble_mod.scan_single") as mock_scan:
            mock_scan.return_value = None

            result = runner.invoke(
                cli,
                ["ble", "scan", "--key", "invalid!!!", "--timeout", "0"],
            )

            # Should report error about invalid key
            assert result.exit_code != 0 or "error" in result.output.lower()

    def test_ble_check_time_help(self, runner):
        """Test ble check-time help."""
        result = runner.invoke(cli, ["ble", "check-time", "--help"])
        assert result.exit_code == 0


class TestOrgCommands:
    """Tests for org subcommands.

    Note: Due to Click's decorator behavior (callbacks use click.decorators globals
    instead of the module globals), integration testing with mocked Organization
    is difficult. The org group callback runs before subcommands and requires
    credentials, so even --help on subcommands requires valid credentials.
    Full Organization behavior is tested in test_org.py.
    """

    def test_org_group_help(self, runner):
        """Test org group help output."""
        result = runner.invoke(cli, ["org", "--help"])
        assert result.exit_code == 0
        assert "Organization utilities" in result.output
        assert "--org-id" in result.output
        assert "--token" in result.output
        # Verify subcommands are listed
        assert "info" in result.output
        assert "list-devices" in result.output
        assert "register-device" in result.output
        assert "get-packets" in result.output

    def test_org_requires_credentials(self, runner):
        """Test org commands fail without credentials."""
        # Running without credentials should fail
        result = runner.invoke(cli, ["org", "info"])
        assert result.exit_code != 0

    @pytest.mark.integration
    def test_org_invalid_credentials_error(self, runner):
        """Test org commands report invalid credentials error."""
        result = runner.invoke(
            cli,
            ["org", "--org-id", "fake-org", "--token", "fake-token", "info"],
        )
        # Should fail with invalid credentials
        assert result.exit_code != 0
        assert "Invalid" in result.output or "credentials" in result.output.lower()


class TestMainFunction:
    """Tests for main() entry point."""

    def test_main_returns_exit_code_0_on_success(self):
        """Test main returns 0 on successful command."""
        exit_code = main(["--help"])
        assert exit_code == 0

    def test_main_returns_nonzero_on_error(self):
        """Test main returns non-zero on error."""
        # Invalid command should return non-zero
        exit_code = main(["nonexistent-command"])
        assert exit_code != 0


class TestOutputFormats:
    """Tests for different output format options."""

    def test_ble_scan_format_options(self, runner):
        """Test that ble scan supports format options."""
        result = runner.invoke(cli, ["ble", "scan", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "tabular" in result.output
        assert "json" in result.output

    def test_ble_detect_format_options(self, runner):
        """Test that ble detect supports format options."""
        result = runner.invoke(cli, ["ble", "detect", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "tabular" in result.output
        assert "json" in result.output


class TestEnvironmentVariableFallback:
    """Tests for environment variable fallback."""

    def test_uses_env_vars_when_options_not_provided(self, runner):
        """Test that environment variables are used when options not provided."""
        mock_env = Environment(name="PROD", url="https://api.hubble.com")

        with patch("hubblenetwork.cli.cloud.get_env_from_credentials") as mock_get_env:
            mock_get_env.return_value = mock_env

            result = runner.invoke(
                cli,
                ["validate-credentials"],
                env={
                    "HUBBLE_ORG_ID": "env-org-id",
                    "HUBBLE_API_TOKEN": "env-token",
                },
            )

            assert result.exit_code == 0
            # Verify credentials were constructed from env vars
            mock_get_env.assert_called_once()
            creds = mock_get_env.call_args[0][0]
            assert creds.org_id == "env-org-id"
            assert creds.api_token == "env-token"
