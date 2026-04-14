"""Tests for the unencrypted Hubble BLE protocol."""
from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from hubblenetwork.ble import parse_unencrypted
from hubblenetwork.packets import UnencryptedPacket, Location
from hubblenetwork.cli import cli


# ---------------------------------------------------------------------------
# parse_unencrypted() unit tests
# ---------------------------------------------------------------------------


def test_parse_unencrypted_valid():
    """Example from the spec: version=1, network_id=4378792717, no payload."""
    data = bytes.fromhex("0504ff130d")
    result = parse_unencrypted(data)
    assert result is not None
    version, network_id, payload = result
    assert version == 1
    assert network_id == 4378792717
    assert payload == b""


def test_parse_unencrypted_with_payload():
    """Header + 2 bytes of customer payload."""
    header = bytes.fromhex("0504ff130d")
    customer = b"\xAB\xCD"
    data = header + customer
    result = parse_unencrypted(data)
    assert result is not None
    version, network_id, payload = result
    assert version == 1
    assert network_id == 4378792717
    assert payload == customer


def test_parse_unencrypted_max_payload():
    """Header + 18 bytes of customer payload (maximum)."""
    header = bytes.fromhex("0504ff130d")
    customer = bytes(range(18))
    data = header + customer
    result = parse_unencrypted(data)
    assert result is not None
    _, _, payload = result
    assert payload == customer
    assert len(payload) == 18


def test_parse_unencrypted_returns_none_for_encrypted():
    """Encrypted packets have version=0 in the top 6 bits; should return None."""
    # First byte 0x00 → top 6 bits are 0 → encrypted
    data = bytes(10)
    assert parse_unencrypted(data) is None


def test_parse_unencrypted_short_data():
    """Data shorter than 5 bytes cannot be an unencrypted header."""
    assert parse_unencrypted(b"") is None
    assert parse_unencrypted(b"\x04\x00\x00\x00") is None


def test_parse_unencrypted_roundtrip():
    """Encode then decode a (version, network_id) pair."""
    version = 1
    network_id = 1234567890
    header_int = (version << 34) | network_id
    data = header_int.to_bytes(5, "big") + b"\xFF"
    result = parse_unencrypted(data)
    assert result is not None
    v, nid, payload = result
    assert v == version
    assert nid == network_id
    assert payload == b"\xFF"


# ---------------------------------------------------------------------------
# UnencryptedPacket dataclass tests
# ---------------------------------------------------------------------------


def test_unencrypted_packet_fields():
    pkt = UnencryptedPacket(
        timestamp=1000000,
        location=Location(lat=37.0, lon=-122.0),
        network_id=4378792717,
        protocol_version=1,
        payload=b"\x01\x02",
        rssi=-60,
    )
    assert pkt.timestamp == 1000000
    assert pkt.network_id == 4378792717
    assert pkt.protocol_version == 1
    assert pkt.payload == b"\x01\x02"
    assert pkt.rssi == -60


def test_unencrypted_packet_frozen():
    pkt = UnencryptedPacket(
        timestamp=0,
        location=None,
        network_id=0,
        protocol_version=1,
        payload=b"",
        rssi=0,
    )
    with pytest.raises(FrozenInstanceError):
        pkt.network_id = 999


# ---------------------------------------------------------------------------
# CLI auto-detection tests (ble scan handles both protocols)
# ---------------------------------------------------------------------------


def _make_unencrypted_packet(**overrides):
    defaults = dict(
        timestamp=1700000000,
        location=Location(lat=90, lon=0, fake=True),
        network_id=4378792717,
        protocol_version=1,
        payload=b"\xAB\xCD",
        rssi=-55,
    )
    defaults.update(overrides)
    return UnencryptedPacket(**defaults)


@patch("hubblenetwork.cli.ble_mod.scan_single")
def test_scan_auto_detects_unencrypted_tabular(mock_scan):
    """ble scan should auto-detect unencrypted packets and show NET_ID column."""
    pkt = _make_unencrypted_packet()
    mock_scan.side_effect = [pkt, None]

    runner = CliRunner()
    result = runner.invoke(cli, ["ble", "scan", "--timeout", "1"])
    assert result.exit_code == 0
    assert "4378792717" in result.output
    assert "NET_ID" in result.output


@patch("hubblenetwork.cli.ble_mod.scan_single")
def test_scan_auto_detects_unencrypted_json(mock_scan):
    """ble scan JSON output should contain unencrypted packet fields."""
    pkt = _make_unencrypted_packet()
    mock_scan.side_effect = [pkt, None]

    runner = CliRunner()
    result = runner.invoke(cli, ["ble", "scan", "--timeout", "1", "-o", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert len(parsed) == 1
    assert parsed[0]["network_id"] == 4378792717
    assert parsed[0]["protocol_version"] == 1
    assert "payload" in parsed[0]


@patch("hubblenetwork.cli.ble_mod.scan_single")
def test_scan_network_id_filter(mock_scan):
    """--network-id should filter out non-matching unencrypted packets."""
    pkt_match = _make_unencrypted_packet(network_id=111)
    pkt_other = _make_unencrypted_packet(network_id=222)
    mock_scan.side_effect = [pkt_other, pkt_match, None]

    runner = CliRunner()
    result = runner.invoke(
        cli, ["ble", "scan", "--timeout", "1", "--network-id", "111", "-o", "json"]
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert len(parsed) == 1
    assert parsed[0]["network_id"] == 111


@patch("hubblenetwork.cli.ble_mod.scan_single")
def test_scan_count_with_unencrypted(mock_scan):
    """-n should stop after N packets (including unencrypted)."""
    pkt = _make_unencrypted_packet()
    mock_scan.side_effect = [pkt, pkt, pkt, None]

    runner = CliRunner()
    result = runner.invoke(
        cli, ["ble", "scan", "--timeout", "1", "-n", "2", "-o", "json"]
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert len(parsed) == 2
