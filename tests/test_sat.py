"""Tests for satellite scanning module and CLI."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from hubblenetwork.cli import cli
from hubblenetwork.errors import DockerError, SatelliteError
from hubblenetwork.packets import SatellitePacket
from hubblenetwork import sat


# ---------------------------------------------------------------------------
# SatellitePacket dataclass
# ---------------------------------------------------------------------------


class TestSatellitePacket:
    def test_creation(self):
        pkt = SatellitePacket(
            device_id="0xBB2973BD",
            seq_num=153,
            device_type="silabs",
            timestamp=1774289859.339,
            rssi_dB=-42.3,
            channel_num=2,
            freq_offset_hz=21654.5,
            payload=b"\xde\xad\xbe\xef",
        )
        assert pkt.device_id == "0xBB2973BD"
        assert pkt.seq_num == 153
        assert pkt.device_type == "silabs"
        assert pkt.timestamp == 1774289859.339
        assert pkt.rssi_dB == -42.3
        assert pkt.channel_num == 2
        assert pkt.freq_offset_hz == 21654.5
        assert pkt.payload == b"\xde\xad\xbe\xef"

    def test_frozen(self):
        pkt = SatellitePacket(
            device_id="0xBB2973BD",
            seq_num=1,
            device_type="silabs",
            timestamp=0.0,
            rssi_dB=0.0,
            channel_num=0,
            freq_offset_hz=0.0,
            payload=b"",
        )
        with pytest.raises(AttributeError):
            pkt.seq_num = 2  # type: ignore[misc]


# ---------------------------------------------------------------------------
# JSONL parsing
# ---------------------------------------------------------------------------

_PAYLOAD_B64 = base64.b64encode(b"\xde\xad\xbe\xef").decode()

SAMPLE_JSONL = (
    '{"device_id": "0xBB2973BD", "seq_num": 153, "device_type": "silabs", '
    '"timestamp": 1774289859.339, "rssi_dB": -42.3, "channel_num": 2, '
    f'"freq_offset_hz": 21654.5, "payload_b64": "{_PAYLOAD_B64}"}}\n'
    '{"device_id": "0xBB2973BD", "seq_num": 154, "device_type": "silabs", '
    '"timestamp": 1774289863.860, "rssi_dB": -42.9, "channel_num": 15, '
    f'"freq_offset_hz": 21588.0, "payload_b64": "{_PAYLOAD_B64}"}}\n'
)


class TestParseJsonl:
    def test_parses_valid_jsonl(self):
        packets = sat._parse_jsonl(SAMPLE_JSONL)
        assert len(packets) == 2
        assert packets[0].device_id == "0xBB2973BD"
        assert packets[0].seq_num == 153
        assert packets[0].payload == b"\xde\xad\xbe\xef"
        assert packets[1].seq_num == 154

    def test_skips_blank_lines(self):
        text = "\n" + SAMPLE_JSONL + "\n\n"
        packets = sat._parse_jsonl(text)
        assert len(packets) == 2

    def test_skips_malformed_lines(self):
        text = "not json\n" + SAMPLE_JSONL
        packets = sat._parse_jsonl(text)
        assert len(packets) == 2

    def test_empty_input(self):
        assert sat._parse_jsonl("") == []
        assert sat._parse_jsonl("\n\n") == []

    def test_missing_field(self):
        text = '{"device_id": "0xAA", "seq_num": 1}\n'
        packets = sat._parse_jsonl(text)
        assert len(packets) == 0  # missing required fields -> skipped

    def test_missing_payload_gives_empty_bytes(self):
        text = (
            '{"device_id": "0xAA", "seq_num": 1, "device_type": "silabs", '
            '"timestamp": 0.0, "rssi_dB": 0.0, "channel_num": 0, '
            '"freq_offset_hz": 0.0}\n'
        )
        packets = sat._parse_jsonl(text)
        assert len(packets) == 1
        assert packets[0].payload == b""


# ---------------------------------------------------------------------------
# Deduplication key
# ---------------------------------------------------------------------------


class TestPacketKey:
    def test_key_tuple(self):
        pkt = SatellitePacket(
            device_id="0xAA",
            seq_num=10,
            device_type="silabs",
            timestamp=0.0,
            rssi_dB=0.0,
            channel_num=0,
            freq_offset_hz=0.0,
            payload=b"",
        )
        assert sat._packet_key(pkt) == ("0xAA", 10)


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------


class TestGetClient:
    @patch("docker.from_env")
    def test_from_env_succeeds(self, mock_from_env):
        mock_client = MagicMock()
        mock_from_env.return_value = mock_client
        assert sat._get_client() is mock_client

    @patch("hubblenetwork.sat._DOCKER_DESKTOP_SOCKETS", [])
    @patch("docker.from_env")
    def test_from_env_fails_no_fallbacks(self, mock_from_env):
        import docker

        mock_from_env.side_effect = docker.errors.DockerException("no sock")
        with pytest.raises(DockerError, match="Docker is not available"):
            sat._get_client()

    @patch("docker.DockerClient")
    @patch("docker.from_env")
    def test_fallback_to_desktop_socket(self, mock_from_env, mock_client_cls, tmp_path):
        import docker

        mock_from_env.side_effect = docker.errors.DockerException("no sock")

        # Create a fake socket file so the path.exists() check passes.
        fake_sock = tmp_path / "docker.sock"
        fake_sock.touch()

        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        with patch("hubblenetwork.sat._DOCKER_DESKTOP_SOCKETS", [fake_sock]):
            result = sat._get_client()

        mock_client_cls.assert_called_once_with(base_url=f"unix://{fake_sock}")
        mock_client.ping.assert_called_once()
        assert result is mock_client

    @patch("docker.DockerClient")
    @patch("docker.from_env")
    def test_fallback_skips_nonexistent_sockets(
        self, mock_from_env, mock_client_cls, tmp_path
    ):
        import docker

        mock_from_env.side_effect = docker.errors.DockerException("no sock")

        missing = tmp_path / "missing.sock"
        existing = tmp_path / "docker.sock"
        existing.touch()

        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        with patch(
            "hubblenetwork.sat._DOCKER_DESKTOP_SOCKETS", [missing, existing]
        ):
            result = sat._get_client()

        # Only the existing socket should be tried.
        mock_client_cls.assert_called_once_with(base_url=f"unix://{existing}")
        assert result is mock_client

    @patch("docker.DockerClient")
    @patch("docker.from_env")
    def test_fallback_skips_socket_that_fails_ping(
        self, mock_from_env, mock_client_cls, tmp_path
    ):
        import docker

        mock_from_env.side_effect = docker.errors.DockerException("no sock")

        bad_sock = tmp_path / "bad.sock"
        bad_sock.touch()
        good_sock = tmp_path / "good.sock"
        good_sock.touch()

        bad_client = MagicMock()
        bad_client.ping.side_effect = Exception("connection refused")
        good_client = MagicMock()

        mock_client_cls.side_effect = [bad_client, good_client]

        with patch(
            "hubblenetwork.sat._DOCKER_DESKTOP_SOCKETS", [bad_sock, good_sock]
        ):
            result = sat._get_client()

        assert result is good_client


class TestDockerHelpers:
    @patch("hubblenetwork.sat._get_client")
    def test_ensure_docker_available_success(self, mock_get_client):
        mock_get_client.return_value = MagicMock()
        sat.ensure_docker_available()  # should not raise
        mock_get_client.assert_called_once()

    @patch("hubblenetwork.sat._get_client")
    def test_ensure_docker_not_available(self, mock_get_client):
        mock_get_client.side_effect = DockerError("Docker is not available")
        with pytest.raises(DockerError, match="not available"):
            sat.ensure_docker_available()

    @patch("hubblenetwork.sat._get_client")
    def test_pull_image_success(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        sat.pull_image("test:latest")
        mock_client.images.pull.assert_called_with("test:latest")

    @patch("hubblenetwork.sat._get_client")
    def test_pull_image_failure(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client
        mock_client.images.pull.side_effect = Exception("network error")
        with pytest.raises(DockerError, match="Failed to pull"):
            sat.pull_image("test:latest")


class TestStartContainer:
    @patch("hubblenetwork.sat._get_client")
    def test_default_privileged(self, mock_get_client):
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_client.containers.run.return_value = mock_container
        mock_get_client.return_value = mock_client

        result = sat.start_container("test:latest", 8050)
        call_kwargs = mock_client.containers.run.call_args[1]
        assert call_kwargs["privileged"] is True
        assert call_kwargs["name"] == sat.CONTAINER_NAME
        assert result == "abc123"

    @patch("hubblenetwork.sat._get_client")
    def test_mock_mode_params(self, mock_get_client):
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "mock123"
        mock_client.containers.run.return_value = mock_container
        mock_get_client.return_value = mock_client

        result = sat.start_container(
            "test:latest",
            8050,
            environment={"SDR_TYPE": "mock"},
            privileged=False,
            name=sat.MOCK_CONTAINER_NAME,
        )
        call_kwargs = mock_client.containers.run.call_args[1]
        assert call_kwargs["privileged"] is False
        assert call_kwargs["environment"] == {"SDR_TYPE": "mock"}
        assert call_kwargs["name"] == "hubble-pluto-sdr-mock"
        assert result == "mock123"


class TestScanMockMode:
    @patch("hubblenetwork.sat.stop_container")
    @patch("hubblenetwork.sat.fetch_packets")
    @patch("hubblenetwork.sat._wait_for_api")
    @patch("hubblenetwork.sat.start_container")
    @patch("hubblenetwork.sat.pull_image")
    @patch("hubblenetwork.sat.ensure_docker_available")
    def test_scan_mock_passes_correct_params(
        self, mock_ensure, mock_pull, mock_start, mock_wait, mock_fetch, mock_stop
    ):
        mock_start.return_value = "container123"
        mock_fetch.return_value = []

        list(sat.scan(timeout=0.1, mock=True))

        mock_start.assert_called_once_with(
            image=sat.DOCKER_IMAGE,
            port=sat.API_PORT,
            environment={"SDR_TYPE": "mock"},
            privileged=False,
            name=sat.MOCK_CONTAINER_NAME,
        )
        mock_stop.assert_called_once_with("container123")

    @patch("hubblenetwork.sat.stop_container")
    @patch("hubblenetwork.sat.fetch_packets")
    @patch("hubblenetwork.sat._wait_for_api")
    @patch("hubblenetwork.sat.start_container")
    @patch("hubblenetwork.sat.pull_image")
    @patch("hubblenetwork.sat.ensure_docker_available")
    def test_scan_real_passes_correct_params(
        self, mock_ensure, mock_pull, mock_start, mock_wait, mock_fetch, mock_stop
    ):
        mock_start.return_value = "container456"
        mock_fetch.return_value = []

        list(sat.scan(timeout=0.1, mock=False))

        mock_start.assert_called_once_with(
            image=sat.DOCKER_IMAGE,
            port=sat.API_PORT,
            environment=None,
            privileged=True,
            name=sat.CONTAINER_NAME,
        )


# ---------------------------------------------------------------------------
# CLI - sat scan
# ---------------------------------------------------------------------------


def _make_sat_pkt(**overrides) -> SatellitePacket:
    defaults = dict(
        device_id="0xBB2973BD",
        seq_num=153,
        device_type="silabs",
        timestamp=1774289859.339,
        rssi_dB=-42.3,
        channel_num=2,
        freq_offset_hz=21654.5,
        payload=b"\xde\xad\xbe\xef",
    )
    defaults.update(overrides)
    return SatellitePacket(**defaults)


class TestSatScanCli:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_help(self, runner):
        result = runner.invoke(cli, ["sat", "scan", "--help"])
        assert result.exit_code == 0
        assert "--timeout" in result.output
        assert "--count" in result.output
        assert "--format" in result.output
        assert "--poll-interval" in result.output
        assert "--payload-format" in result.output

    def test_sat_group_help(self, runner):
        result = runner.invoke(cli, ["sat", "--help"])
        assert result.exit_code == 0
        assert "scan" in result.output

    @patch("hubblenetwork.cli.sat_mod")
    def test_scan_tabular_output(self, mock_sat, runner):
        mock_sat.scan.return_value = iter([_make_sat_pkt()])
        mock_sat.DockerError = DockerError
        mock_sat.SatelliteError = SatelliteError

        result = runner.invoke(
            cli, ["sat", "scan", "--timeout", "1", "--poll-interval", "0.1"]
        )
        assert result.exit_code == 0
        assert "0xBB2973BD" in result.output
        assert "153" in result.output

    @patch("hubblenetwork.cli.sat_mod")
    def test_scan_json_output(self, mock_sat, runner):
        mock_sat.scan.return_value = iter([_make_sat_pkt()])
        mock_sat.DockerError = DockerError
        mock_sat.SatelliteError = SatelliteError

        result = runner.invoke(
            cli,
            ["sat", "scan", "-o", "json", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "[" in result.output
        assert "0xBB2973BD" in result.output
        assert "payload" in result.output

    @patch("hubblenetwork.cli.sat_mod")
    def test_scan_count_limit(self, mock_sat, runner):
        pkts = [_make_sat_pkt(seq_num=i) for i in range(10)]
        mock_sat.scan.return_value = iter(pkts)
        mock_sat.DockerError = DockerError
        mock_sat.SatelliteError = SatelliteError

        result = runner.invoke(
            cli,
            ["sat", "scan", "-n", "3", "--timeout", "5", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "3 packet(s) received" in result.output

    @patch("hubblenetwork.cli.sat_mod")
    def test_docker_not_available(self, mock_sat, runner):
        mock_sat.scan.side_effect = DockerError("Docker is not installed")
        mock_sat.DockerError = DockerError
        mock_sat.SatelliteError = SatelliteError

        result = runner.invoke(cli, ["sat", "scan", "--timeout", "1"])
        assert result.exit_code != 0
        assert "Docker is not installed" in result.output


# ---------------------------------------------------------------------------
# CLI - sat mock-scan
# ---------------------------------------------------------------------------


class TestSatMockScanCli:
    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_help(self, runner):
        result = runner.invoke(cli, ["sat", "mock-scan", "--help"])
        assert result.exit_code == 0
        assert "--timeout" in result.output
        assert "--count" in result.output
        assert "--format" in result.output
        assert "mock" in result.output.lower()

    def test_listed_in_sat_help(self, runner):
        result = runner.invoke(cli, ["sat", "--help"])
        assert result.exit_code == 0
        assert "mock-scan" in result.output

    @patch("hubblenetwork.cli.sat_mod")
    def test_mock_scan_tabular_output(self, mock_sat, runner):
        mock_sat.scan.return_value = iter([_make_sat_pkt()])
        mock_sat.DockerError = DockerError
        mock_sat.SatelliteError = SatelliteError

        result = runner.invoke(
            cli, ["sat", "mock-scan", "--timeout", "1", "--poll-interval", "0.1"]
        )
        assert result.exit_code == 0
        assert "0xBB2973BD" in result.output
        # Verify mock=True was passed
        mock_sat.scan.assert_called_once()
        assert mock_sat.scan.call_args[1].get("mock") is True

    @patch("hubblenetwork.cli.sat_mod")
    def test_mock_scan_json_output(self, mock_sat, runner):
        mock_sat.scan.return_value = iter([_make_sat_pkt()])
        mock_sat.DockerError = DockerError
        mock_sat.SatelliteError = SatelliteError

        result = runner.invoke(
            cli,
            ["sat", "mock-scan", "-o", "json", "--timeout", "1", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "0xBB2973BD" in result.output

    @patch("hubblenetwork.cli.sat_mod")
    def test_mock_scan_count_limit(self, mock_sat, runner):
        pkts = [_make_sat_pkt(seq_num=i) for i in range(10)]
        mock_sat.scan.return_value = iter(pkts)
        mock_sat.DockerError = DockerError
        mock_sat.SatelliteError = SatelliteError

        result = runner.invoke(
            cli,
            ["sat", "mock-scan", "-n", "3", "--timeout", "5", "--poll-interval", "0.1"],
        )
        assert result.exit_code == 0
        assert "3 packet(s) received" in result.output

    @patch("hubblenetwork.cli.sat_mod")
    def test_docker_not_available(self, mock_sat, runner):
        mock_sat.scan.side_effect = DockerError("Docker is not installed")
        mock_sat.DockerError = DockerError
        mock_sat.SatelliteError = SatelliteError

        result = runner.invoke(cli, ["sat", "mock-scan", "--timeout", "1"])
        assert result.exit_code != 0
        assert "Docker is not installed" in result.output
