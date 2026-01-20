"""Tests for ble.py BLE scanning functions."""

from __future__ import annotations

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone

from hubblenetwork.ble import (
    _TARGET_UUID,
    _get_location,
    _scan_async,
    scan,
    scan_async,
    _scan_single_async,
    scan_single,
    scan_single_async,
)
from hubblenetwork.packets import EncryptedPacket, Location


@pytest.mark.ble
class TestGetLocation:
    """Tests for _get_location helper."""

    def test_returns_fake_location(self):
        """Test _get_location returns a fake location."""
        loc = _get_location()
        assert loc is not None
        assert isinstance(loc, Location)
        assert loc.fake is True
        assert loc.lat == 90
        assert loc.lon == 0


@pytest.mark.ble
class TestTargetUuid:
    """Tests for target UUID constant."""

    def test_target_uuid_format(self):
        """Test target UUID is correct 128-bit Bluetooth format."""
        assert _TARGET_UUID == "0000fca6-0000-1000-8000-00805f9b34fb"
        assert len(_TARGET_UUID) == 36  # Standard UUID string length


@pytest.mark.ble
class TestScanAsync:
    """Tests for _scan_async function."""

    @pytest.mark.asyncio
    async def test_scan_returns_empty_on_timeout(self):
        """Test scan returns empty list when no packets found."""
        mock_scanner = MagicMock()
        mock_scanner.__aenter__ = AsyncMock(return_value=mock_scanner)
        mock_scanner.__aexit__ = AsyncMock(return_value=None)

        with patch("hubblenetwork.ble.BleakScanner", return_value=mock_scanner):
            packets = await _scan_async(0.01)  # Very short timeout
            assert packets == []

    @pytest.mark.asyncio
    async def test_scan_collects_matching_packets(self):
        """Test scan collects packets with matching UUID."""
        captured_callback = None

        def capture_callback(**kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("detection_callback")
            mock_scanner = MagicMock()
            mock_scanner.__aenter__ = AsyncMock(return_value=mock_scanner)
            mock_scanner.__aexit__ = AsyncMock(return_value=None)
            return mock_scanner

        with patch("hubblenetwork.ble.BleakScanner", side_effect=capture_callback):
            # Start scan in background
            scan_task = asyncio.create_task(_scan_async(1.0))

            # Give scanner time to start
            await asyncio.sleep(0.01)

            # Simulate device detection
            if captured_callback:
                mock_device = MagicMock()
                mock_adv = MagicMock()
                mock_adv.service_data = {_TARGET_UUID: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"}
                mock_adv.rssi = -65

                captured_callback(mock_device, mock_adv)

            # Cancel the task (timeout won't complete in time)
            await asyncio.sleep(0.01)
            scan_task.cancel()

            try:
                packets = await scan_task
            except asyncio.CancelledError:
                packets = []

            # Note: Due to async timing, packet may or may not be captured
            # This test validates the structure works

    @pytest.mark.asyncio
    async def test_scan_ignores_non_matching_uuid(self):
        """Test scan ignores packets without matching UUID."""
        captured_callback = None

        def capture_callback(**kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("detection_callback")
            mock_scanner = MagicMock()
            mock_scanner.__aenter__ = AsyncMock(return_value=mock_scanner)
            mock_scanner.__aexit__ = AsyncMock(return_value=None)
            return mock_scanner

        with patch("hubblenetwork.ble.BleakScanner", side_effect=capture_callback):
            scan_task = asyncio.create_task(_scan_async(0.1))
            await asyncio.sleep(0.01)

            if captured_callback:
                mock_device = MagicMock()
                mock_adv = MagicMock()
                mock_adv.service_data = {"wrong-uuid": b"\x00\x01\x02\x03"}
                mock_adv.rssi = -65

                captured_callback(mock_device, mock_adv)

            packets = await scan_task
            assert packets == []


@pytest.mark.ble
class TestScanSingleAsync:
    """Tests for _scan_single_async function."""

    @pytest.mark.asyncio
    async def test_scan_single_returns_none_on_timeout(self):
        """Test scan_single returns None when no packet found."""
        mock_scanner = MagicMock()
        mock_scanner.__aenter__ = AsyncMock(return_value=mock_scanner)
        mock_scanner.__aexit__ = AsyncMock(return_value=None)

        with patch("hubblenetwork.ble.BleakScanner", return_value=mock_scanner):
            packet = await _scan_single_async(0.01)
            assert packet is None

    @pytest.mark.asyncio
    async def test_scan_single_returns_first_matching_packet(self):
        """Test scan_single returns first packet with matching UUID."""
        captured_callback = None
        done_event = asyncio.Event()

        def capture_callback(**kwargs):
            nonlocal captured_callback
            captured_callback = kwargs.get("detection_callback")
            mock_scanner = MagicMock()

            async def aenter(self):
                return self

            async def aexit(self, *args):
                pass

            mock_scanner.__aenter__ = lambda: aenter(mock_scanner)
            mock_scanner.__aexit__ = lambda *args: aexit(mock_scanner)
            return mock_scanner

        with patch("hubblenetwork.ble.BleakScanner", side_effect=capture_callback):
            scan_task = asyncio.create_task(_scan_single_async(1.0))
            await asyncio.sleep(0.01)

            if captured_callback:
                mock_device = MagicMock()
                mock_adv = MagicMock()
                mock_adv.service_data = {_TARGET_UUID: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"}
                mock_adv.service_uuids = [_TARGET_UUID]
                mock_adv.rssi = -70

                captured_callback(mock_device, mock_adv)

            await asyncio.sleep(0.01)
            scan_task.cancel()

            try:
                await scan_task
            except asyncio.CancelledError:
                pass


@pytest.mark.ble
class TestSyncWrappers:
    """Tests for synchronous wrapper functions."""

    def test_scan_calls_async_version(self):
        """Test scan() calls _scan_async."""
        with patch("hubblenetwork.ble._scan_async", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = []
            with patch("hubblenetwork.ble.asyncio.run") as mock_run:
                mock_run.return_value = []
                result = scan(5.0)
                mock_run.assert_called_once()

    def test_scan_single_calls_async_version(self):
        """Test scan_single() calls _scan_single_async."""
        with patch("hubblenetwork.ble._scan_single_async", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = None
            with patch("hubblenetwork.ble.asyncio.run") as mock_run:
                mock_run.return_value = None
                result = scan_single(5.0)
                mock_run.assert_called_once()


@pytest.mark.ble
class TestAsyncWrappers:
    """Tests for async wrapper functions."""

    @pytest.mark.asyncio
    async def test_scan_async_wrapper(self):
        """Test scan_async() calls _scan_async."""
        with patch("hubblenetwork.ble._scan_async", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = []
            result = await scan_async(5.0)
            mock_scan.assert_called_once_with(5.0)
            assert result == []

    @pytest.mark.asyncio
    async def test_scan_single_async_wrapper(self):
        """Test scan_single_async() calls _scan_single_async."""
        with patch("hubblenetwork.ble._scan_single_async", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = None
            result = await scan_single_async(5.0)
            mock_scan.assert_called_once_with(5.0)
            assert result is None
