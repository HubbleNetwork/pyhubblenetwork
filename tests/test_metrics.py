"""Tests for metrics devices command."""
import json

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from hubblenetwork.org import Organization
from hubblenetwork.errors import BackendError
from hubblenetwork.cli import cli


SAMPLE_RESPONSE = {
    "buckets": [
        {
            "timestamp": "2023-10-27T10:00:00Z",
            "registered_devices": 1000,
            "active_devices": 800,
            "never_active_devices": 200,
        },
        {
            "timestamp": "2023-10-28T10:00:00Z",
            "registered_devices": 1050,
            "active_devices": 820,
            "never_active_devices": 230,
        },
    ],
    "total_active_devices": 850,
    "total_registered_devices": 1050,
    "total_never_active_devices": 230,
}


class TestCloudDeviceMetrics:
    def test_calls_cloud_request_with_correct_params(self):
        from hubblenetwork import cloud

        creds = MagicMock()
        creds.org_id = "org-123"
        env = MagicMock()

        with patch("hubblenetwork.cloud.cloud_request") as mock_req:
            mock_req.return_value = (SAMPLE_RESPONSE, None)
            cloud.device_metrics(credentials=creds, env=env, days_back=7)

        mock_req.assert_called_once_with(
            method="GET",
            path="/org/org-123/device_metrics",
            credentials=creds,
            env=env,
            params={"daysBack": 7},
        )

    def test_default_days_back_is_1(self):
        from hubblenetwork import cloud

        creds = MagicMock()
        creds.org_id = "org-123"
        env = MagicMock()

        with patch("hubblenetwork.cloud.cloud_request") as mock_req:
            mock_req.return_value = (SAMPLE_RESPONSE, None)
            cloud.device_metrics(credentials=creds, env=env)

        call_params = mock_req.call_args[1]["params"]
        assert call_params["daysBack"] == 1

    def test_returns_json_response(self):
        from hubblenetwork import cloud

        creds = MagicMock()
        creds.org_id = "org-123"
        env = MagicMock()

        with patch("hubblenetwork.cloud.cloud_request") as mock_req:
            mock_req.return_value = (SAMPLE_RESPONSE, None)
            result = cloud.device_metrics(credentials=creds, env=env)

        assert result == SAMPLE_RESPONSE


class TestOrgDeviceMetrics:
    def test_delegates_to_cloud_function(self):
        org = MagicMock(spec=Organization)
        org.credentials = MagicMock()
        org.env = MagicMock()

        with patch("hubblenetwork.org.cloud.device_metrics") as mock_metrics:
            mock_metrics.return_value = SAMPLE_RESPONSE
            Organization.device_metrics(org, days_back=3)

        mock_metrics.assert_called_once_with(
            credentials=org.credentials,
            env=org.env,
            days_back=3,
        )

    def test_propagates_backend_error(self):
        org = MagicMock(spec=Organization)
        org.credentials = MagicMock()
        org.env = MagicMock()

        with patch(
            "hubblenetwork.org.cloud.device_metrics",
            side_effect=BackendError("500: internal error"),
        ):
            with pytest.raises(BackendError):
                Organization.device_metrics(org)


class TestMetricsDevicesCLI:
    def test_table_output_default(self):
        runner = CliRunner()

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            mock_org.device_metrics.return_value = SAMPLE_RESPONSE
            result = runner.invoke(
                cli,
                ["metrics", "--org-id", "fake-org", "--token", "fake-token", "devices"],
            )

        assert result.exit_code == 0
        assert "TIMESTAMP" in result.output
        assert "REGISTERED" in result.output
        assert "ACTIVE" in result.output
        assert "NEVER ACTIVE" in result.output
        assert "1000" in result.output
        assert "Totals:" in result.output
        assert "1050" in result.output

    def test_json_output(self):
        runner = CliRunner()

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            mock_org.device_metrics.return_value = SAMPLE_RESPONSE
            result = runner.invoke(
                cli,
                ["metrics", "--org-id", "fake-org", "--token", "fake-token",
                 "devices", "-o", "json"],
            )

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "buckets" in parsed
        assert parsed["total_active_devices"] == 850
        assert len(parsed["buckets"]) == 2

    def test_days_option_passed_through(self):
        runner = CliRunner()

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            mock_org.device_metrics.return_value = SAMPLE_RESPONSE
            runner.invoke(
                cli,
                ["metrics", "--org-id", "fake-org", "--token", "fake-token",
                 "devices", "--days", "7"],
            )

        mock_org.device_metrics.assert_called_once_with(days_back=7)

    def test_empty_buckets_shows_message(self):
        runner = CliRunner()
        empty_response = {
            "buckets": [],
            "total_active_devices": 0,
            "total_registered_devices": 0,
            "total_never_active_devices": 0,
        }

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org_cls.return_value = MagicMock(spec=Organization)
            mock_org = mock_org_cls.return_value
            mock_org.device_metrics.return_value = empty_response
            result = runner.invoke(
                cli,
                ["metrics", "--org-id", "fake-org", "--token", "fake-token", "devices"],
            )

        assert result.exit_code == 0
        assert "No bucket data available." in result.output
        assert "Totals:" in result.output
