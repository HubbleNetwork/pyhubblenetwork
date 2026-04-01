"""Integration tests for satellite mock scanning (requires Docker)."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from hubblenetwork import sat
from hubblenetwork.cli import cli

pytestmark = pytest.mark.docker


class TestMockScanAPI:
    """End-to-end tests using the Python API with a real Docker container."""

    @pytest.fixture(scope="class")
    def mock_packets(self):
        """Run a single mock scan and share the result across all tests."""
        return list(sat.scan(timeout=20, poll_interval=1.0, mock=True))

    def test_receives_packets(self, mock_packets):
        assert len(mock_packets) >= 1
        pkt = mock_packets[0]
        assert pkt.device_id
        assert isinstance(pkt.seq_num, int)
        assert isinstance(pkt.device_type, str)
        assert isinstance(pkt.timestamp, float)
        assert isinstance(pkt.rssi_dB, float)
        assert isinstance(pkt.channel_num, int)
        assert isinstance(pkt.freq_offset_hz, float)

    def test_deduplication(self, mock_packets):
        keys = [(p.device_id, p.seq_num) for p in mock_packets]
        assert len(keys) == len(set(keys)), "Duplicate packets detected"

    def test_multiple_devices(self, mock_packets):
        device_ids = {p.device_id for p in mock_packets}
        assert len(device_ids) >= 2, f"Expected multiple mock devices, got {device_ids}"


class TestMockScanCLI:
    """End-to-end tests using the CLI with a real Docker container."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_json_output(self, runner):
        result = runner.invoke(
            cli,
            ["sat", "mock-scan", "-o", "json", "--timeout", "15", "-n", "2"],
        )
        assert result.exit_code == 0
        # JSON mode wraps output in an array
        data = json.loads(result.output)
        assert len(data) >= 1
        pkt = data[0]
        assert "device_id" in pkt
        assert "seq_num" in pkt
        assert "timestamp" in pkt
        assert "payload" in pkt

    def test_tabular_output(self, runner):
        result = runner.invoke(
            cli,
            ["sat", "mock-scan", "--timeout", "15", "-n", "2"],
        )
        assert result.exit_code == 0
        assert "packet(s) received" in result.output
