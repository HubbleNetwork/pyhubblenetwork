"""BLE scanning holds one scanner open for the whole scan.

The SDK used to build a fresh BleakScanner inside a fresh asyncio.run() for
every packet, and the CLI called that in a loop. macOS tolerates it because
CoreBluetooth is in-process. Linux does not: each iteration is a full round
trip to bluetoothd over D-Bus, BlueZ serialises discovery state machine-wide,
and bleak force-finalises the dbus-fast bus belonging to any event loop that
has closed. The crash arrived after roughly as many packets as there had been
loop teardowns, which is how it read as "crashes after a few decoded packets".

These tests count scanner lifecycles, so the churn cannot come back quietly.
"""

import asyncio
from typing import ClassVar

import pytest

from hubblenetwork import ble

_UUID = "0000fca6-0000-1000-8000-00805f9b34fb"

# An unencrypted (version 1) advertisement: cheap to build, parses cleanly.
_RAW = bytes([0x04, 0x05, 0x06, 0x07, 0x08]) + b"hello"


class _Adv:
    def __init__(self, raw=_RAW, rssi=-62):
        self.service_data = {_UUID: raw}
        self.rssi = rssi


class _FakeScanner:
    """Stands in for BleakScanner and records its own lifecycle.

    `feed` is the list of advertisements to deliver, queued with call_soon so
    they all land in the callback before the consumer is handed the first one.
    That is the burst the old design threw away.
    """

    instances: ClassVar[list] = []
    feed: ClassVar[list] = []

    def __init__(self, detection_callback=None, **kwargs):
        self.detection_callback = detection_callback
        self.entered = 0
        self.exited = 0
        _FakeScanner.instances.append(self)

    async def __aenter__(self):
        self.entered += 1
        loop = asyncio.get_running_loop()
        for adv in _FakeScanner.feed:
            loop.call_soon(self.detection_callback, None, adv)
        return self

    async def __aexit__(self, *exc_info):
        self.exited += 1
        return False


@pytest.fixture
def fake_scanner(monkeypatch):
    _FakeScanner.instances = []
    _FakeScanner.feed = []
    monkeypatch.setattr(ble, "BleakScanner", _FakeScanner)
    return _FakeScanner


class TestOneScannerPerScan:
    def test_many_packets_use_a_single_scanner(self, fake_scanner):
        """The regression guard. Six packets used to mean six scanners, six
        event loops and six StartDiscovery/StopDiscovery pairs."""
        fake_scanner.feed = [_Adv() for _ in range(6)]

        packets = list(ble.scan_stream(timeout=0.2))

        assert len(packets) == 6
        assert len(fake_scanner.instances) == 1
        assert fake_scanner.instances[0].entered == 1
        assert fake_scanner.instances[0].exited == 1

    def test_buffered_scan_also_uses_one_scanner(self, fake_scanner):
        fake_scanner.feed = [_Adv() for _ in range(4)]

        packets = ble.scan(timeout=0.2)

        assert len(packets) == 4
        assert len(fake_scanner.instances) == 1

    def test_breaking_out_early_still_stops_the_scanner(self, fake_scanner):
        """A consumer that stops at N (`ble scan -n N`) must not leave
        discovery running."""
        fake_scanner.feed = [_Adv() for _ in range(5)]

        stream = ble.scan_stream(timeout=None)
        taken = []
        for packet in stream:
            taken.append(packet)
            if len(taken) == 2:
                break
        stream.close()

        assert len(taken) == 2
        assert len(fake_scanner.instances) == 1
        assert fake_scanner.instances[0].exited == 1

    def test_scan_single_is_still_one_packet(self, fake_scanner):
        fake_scanner.feed = [_Adv(), _Adv()]

        packet = ble.scan_single(timeout=0.2)

        assert packet is not None
        assert len(fake_scanner.instances) == 1
        assert fake_scanner.instances[0].exited == 1

    def test_scan_single_returns_none_on_an_empty_window(self, fake_scanner):
        assert ble.scan_single(timeout=0.05) is None
        assert fake_scanner.instances[0].exited == 1


class TestNoPacketsDropped:
    def test_a_burst_arriving_together_is_all_delivered(self, fake_scanner):
        """Adverts that land while the consumer is busy wait in the queue.

        The old design was deaf between packets: everything advertised between
        one scanner stopping and the next starting was simply gone.
        """
        fake_scanner.feed = [_Adv(rssi=-40 - i) for i in range(10)]

        rssis = [p.rssi for p in ble.scan_stream(timeout=0.2)]

        assert rssis == [-40 - i for i in range(10)]

    def test_a_slow_consumer_does_not_lose_the_backlog(self, fake_scanner):
        fake_scanner.feed = [_Adv() for _ in range(5)]

        seen = 0
        for _packet in ble.scan_stream(timeout=0.5):
            seen += 1
            # Stand-in for the work the CLI does per row.
            sum(range(10_000))

        assert seen == 5


class TestTimeoutIsTheWholeWindow:
    def test_empty_window_ends_without_packets(self, fake_scanner):
        assert list(ble.scan_stream(timeout=0.05)) == []
        assert len(fake_scanner.instances) == 1

    def test_non_hubble_adverts_are_ignored(self, fake_scanner):
        other = _Adv()
        other.service_data = {"0000fca7-0000-1000-8000-00805f9b34fb": b"\x01\x02"}
        fake_scanner.feed = [other]

        assert list(ble.scan_stream(timeout=0.05)) == []


class TestSyncCallInsideAnEventLoop:
    """The old handler caught RuntimeError from asyncio.run() and could not tell
    a Jupyter problem from a BlueZ one. In the CLI there is never a running
    loop, so a real BlueZ RuntimeError fell through to "build another loop and
    re-run the whole scan": the error never printed and the scan silently
    happened twice.
    """

    def test_stream_refuses_and_says_what_to_use(self, fake_scanner):
        async def inner():
            with pytest.raises(RuntimeError, match="scan_stream_async"):
                ble.scan_stream(timeout=1)

        asyncio.run(inner())

    def test_the_refusal_is_immediate_not_on_first_next(self, fake_scanner):
        """Raised when called, so the caller isn't told at the wrong moment."""

        async def inner():
            with pytest.raises(RuntimeError):
                ble.scan_stream(timeout=1)
            assert fake_scanner.instances == []

        asyncio.run(inner())

    def test_scan_single_refuses_too(self, fake_scanner):
        async def inner():
            with pytest.raises(RuntimeError, match="scan_stream_async"):
                ble.scan_single(timeout=1)

        asyncio.run(inner())

    def test_a_bluez_runtime_error_propagates_instead_of_rescanning(
        self, fake_scanner, monkeypatch
    ):
        """dbus-fast raises RuntimeError too. It must reach the caller once,
        not trigger a silent retry on a fresh loop."""
        attempts = []

        class _Exploding(_FakeScanner):
            async def __aenter__(self):
                attempts.append(1)
                raise RuntimeError("Event loop is closed")

        monkeypatch.setattr(ble, "BleakScanner", _Exploding)

        with pytest.raises(RuntimeError, match="Event loop is closed"):
            list(ble.scan_stream(timeout=0.1))

        assert len(attempts) == 1


class TestAsyncApi:
    def test_stream_async_yields_every_packet(self, fake_scanner):
        fake_scanner.feed = [_Adv() for _ in range(3)]

        async def inner():
            return [p async for p in ble.scan_stream_async(timeout=0.2)]

        assert len(asyncio.run(inner())) == 3
        assert len(fake_scanner.instances) == 1

    def test_scan_async_buffers_the_window(self, fake_scanner):
        fake_scanner.feed = [_Adv() for _ in range(3)]
        assert len(asyncio.run(ble.scan_async(0.2))) == 3

    def test_scan_single_async_stops_the_scanner(self, fake_scanner):
        fake_scanner.feed = [_Adv(), _Adv()]

        packet = asyncio.run(ble.scan_single_async(0.2))

        assert packet is not None
        assert fake_scanner.instances[0].exited == 1


class TestInterruptStillStopsDiscovery:
    """Ctrl+C is the normal way to end `ble scan`, so it is the path most
    likely to leave BlueZ discovering if cleanup is skipped."""

    def test_closing_after_an_interrupt_exits_the_scanner(self, fake_scanner):
        """An abandoned generator stays suspended, holding the scanner, until
        something collects it. close() is what makes cleanup deterministic,
        which is why every CLI command closes its stream in a finally."""
        fake_scanner.feed = [_Adv() for _ in range(3)]

        stream = ble.scan_stream(timeout=None)
        with pytest.raises(KeyboardInterrupt):
            for _packet in stream:
                raise KeyboardInterrupt
        assert fake_scanner.instances[0].exited == 0

        stream.close()
        assert fake_scanner.instances[0].exited == 1

    def test_ble_check_time_closes_its_stream(self, fake_scanner):
        from click.testing import CliRunner

        from hubblenetwork.cli import cli

        fake_scanner.feed = [_Adv() for _ in range(3)]
        CliRunner().invoke(cli, ["ble", "check-time", "-t", "1", "-k", "00" * 16])

        assert len(fake_scanner.instances) == 1
        assert fake_scanner.instances[0].exited == 1

    def test_ble_detect_closes_its_stream(self, fake_scanner):
        from click.testing import CliRunner

        from hubblenetwork.cli import cli

        fake_scanner.feed = [_Adv() for _ in range(3)]
        CliRunner().invoke(cli, ["ble", "detect", "-t", "1", "-k", "00" * 16])

        assert fake_scanner.instances[0].exited == 1

    def test_ble_scan_survives_an_interrupt_and_still_summarises(
        self, fake_scanner, monkeypatch
    ):
        from click.testing import CliRunner

        from hubblenetwork import cli as cli_mod

        fake_scanner.feed = [_Adv() for _ in range(3)]

        real = cli_mod._StreamingTablePrinter.print_row

        def boom(self, *args, **kwargs):
            real(self, *args, **kwargs)
            raise KeyboardInterrupt

        monkeypatch.setattr(cli_mod._StreamingTablePrinter, "print_row", boom)

        res = CliRunner().invoke(cli_mod.cli, ["ble", "scan", "-t", "1"])

        assert res.exit_code == 0
        assert fake_scanner.instances[0].exited == 1


class TestCliOpensOneScanner:
    """End-to-end guard. The SDK API above can stay honest while a CLI loop
    quietly reintroduces the churn, so these drive the real commands with only
    BleakScanner faked out.
    """

    @staticmethod
    def _run(args):
        from click.testing import CliRunner

        from hubblenetwork.cli import cli

        return CliRunner().invoke(cli, args)

    def test_ble_scan_opens_one_scanner_for_many_packets(self, fake_scanner):
        fake_scanner.feed = [_Adv() for _ in range(6)]

        res = self._run(["ble", "scan", "-t", "1"])

        assert res.exit_code == 0
        assert len(fake_scanner.instances) == 1

    def test_ble_scan_count_stops_without_waiting_for_another_packet(
        self, fake_scanner
    ):
        """`-n 2` with no --timeout must return on the 2nd packet. Checking the
        limit before pulling meant blocking for a 3rd it would then discard,
        which never arrives when a device goes quiet.
        """
        fake_scanner.feed = [_Adv() for _ in range(2)]

        res = self._run(["ble", "scan", "-n", "2", "-o", "json"])

        assert res.exit_code == 0
        import json

        assert len(json.loads(res.stdout)) == 2
        assert len(fake_scanner.instances) == 1

    def test_ble_check_time_opens_one_scanner(self, fake_scanner):
        fake_scanner.feed = [_Adv() for _ in range(4)]

        res = self._run(
            ["ble", "check-time", "-t", "1", "-k", "00" * 16]
        )

        assert len(fake_scanner.instances) == 1
        assert res.exit_code == 0

    def test_ble_detect_opens_one_scanner(self, fake_scanner):
        fake_scanner.feed = [_Adv() for _ in range(4)]

        res = self._run(["ble", "detect", "-t", "1", "-k", "00" * 16])

        # Unencrypted adverts never decrypt, so detect reports no valid packet.
        assert len(fake_scanner.instances) == 1
        assert "No valid packets" in res.output
