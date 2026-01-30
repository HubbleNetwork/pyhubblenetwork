# hubblenetwork/cli.py
from __future__ import annotations

import click
import os
import json
import sys
import time
import base64
import binascii
import logging
from datetime import datetime
from typing import Optional, List
from tabulate import tabulate
from hubblenetwork import Organization
from hubblenetwork import Device, DecryptedPacket, EncryptedPacket
from hubblenetwork import ble as ble_mod
from hubblenetwork import ready as ready_mod
from hubblenetwork import decrypt
from hubblenetwork.crypto import find_time_counter_delta
from hubblenetwork import cloud
from hubblenetwork import InvalidCredentialsError

# Set up logger for CLI (outputs to stderr)
logger = logging.getLogger(__name__)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
logger.addHandler(_handler)


def _get_env_or_fail(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise click.ClickException(f"[ERROR] {name} environment variable not set")
    return val


def _get_org_and_token(org_id, token) -> tuple[str, str]:
    """
    Helper function that checks if the given token and/or org
    are None and gets the env var if not
    """
    if not token:
        token = _get_env_or_fail("HUBBLE_API_TOKEN")
    if not org_id:
        org_id = _get_env_or_fail("HUBBLE_ORG_ID")
    return org_id, token


def _packet_to_dict(pkt) -> dict:
    """Convert a packet to a dictionary for JSON serialization."""
    ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
    data = {
        "timestamp": pkt.timestamp,
        "datetime": ts,
        "rssi": pkt.rssi,
    }

    if isinstance(pkt, DecryptedPacket):
        data["counter"] = pkt.counter
        data["sequence"] = pkt.sequence
        # Decode payload to string if possible, otherwise use hex
        try:
            data["payload"] = (
                pkt.payload.decode("utf-8")
                if isinstance(pkt.payload, bytes)
                else str(pkt.payload)
            )
        except UnicodeDecodeError:
            data["payload_hex"] = (
                pkt.payload.hex()
                if isinstance(pkt.payload, bytes)
                else str(pkt.payload)
            )
    else:
        # EncryptedPacket - show payload as hex
        data["payload_hex"] = (
            pkt.payload.hex() if isinstance(pkt.payload, bytes) else str(pkt.payload)
        )

    if not pkt.location.fake:
        data["location"] = {
            "lat": pkt.location.lat,
            "lon": pkt.location.lon,
        }

    return data


class _StreamingPrinterBase:
    """Base class for streaming packet printers."""

    def __init__(self):
        self._packet_count = 0

    def print_row(self, pkt) -> None:
        """Print a single packet. Override in subclasses."""
        raise NotImplementedError

    def finalize(self) -> None:
        """Called when scanning is complete. Override in subclasses if needed."""
        pass

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def suppress_info_messages(self) -> bool:
        """Return True to suppress info messages (e.g., for JSON output)."""
        return False


class _StreamingTablePrinter(_StreamingPrinterBase):
    """Print table rows as they arrive, printing header once."""

    # Fixed column widths for consistent alignment
    _COL_WIDTHS = {
        "TIMESTAMP": 12,
        "TIME": 26,
        "RSSI": 6,
        "COUNTER": 8,
        "SEQ": 6,
        "COORDINATES": 22,
        "PAYLOAD": 20,
    }

    def __init__(self):
        super().__init__()
        self._header_printed = False
        self._headers: List[str] = []
        self._column_config: dict = {}

    def _determine_columns(self, pkt) -> tuple[List[str], dict]:
        """Determine column headers and configuration based on packet type."""
        is_decrypted = isinstance(pkt, DecryptedPacket)
        has_real_location = not pkt.location.fake

        headers = ["TIMESTAMP", "TIME", "RSSI"]
        if is_decrypted:
            headers.extend(["COUNTER", "SEQ"])
        if has_real_location:
            headers.append("COORDINATES")
        if is_decrypted:
            headers.append("PAYLOAD")

        return headers, {
            "is_decrypted": is_decrypted,
            "has_real_location": has_real_location,
        }

    def _format_row(self, values: List) -> str:
        """Format a row with fixed column widths."""
        parts = []
        for i, val in enumerate(values):
            width = self._COL_WIDTHS.get(self._headers[i], 10)
            parts.append(f"{str(val):<{width}}")
        return "| " + " | ".join(parts) + " |"

    def _make_separator(self) -> str:
        """Create a separator line based on current headers."""
        parts = []
        for header in self._headers:
            width = self._COL_WIDTHS.get(header, 10)
            parts.append("-" * width)
        return "+-" + "-+-".join(parts) + "-+"

    def print_row(self, pkt) -> None:
        """Print a single packet row, printing header first if needed."""
        if not self._header_printed:
            self._headers, self._column_config = self._determine_columns(pkt)
            # Print header with separator
            click.echo("")
            click.echo(self._make_separator())
            click.secho(self._format_row(self._headers), bold=True)
            click.echo(self._make_separator())
            self._header_printed = True

        # Build row data matching the column structure
        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
        row = [pkt.timestamp, ts, pkt.rssi if pkt.rssi is not None else "None"]

        if self._column_config["is_decrypted"]:
            row.extend([pkt.counter, pkt.sequence])

        if self._column_config["has_real_location"]:
            loc = pkt.location
            row.append(f"{loc.lat:.6f},{loc.lon:.6f}")

        if self._column_config["is_decrypted"]:
            row.append(f'"{pkt.payload}"')

        # Print the data row
        click.echo(self._format_row(row))
        click.echo(self._make_separator())
        self._packet_count += 1


class _StreamingJsonPrinter(_StreamingPrinterBase):
    """Print packets as a streaming JSON array."""

    def __init__(self):
        super().__init__()
        self._array_started = False

    @property
    def suppress_info_messages(self) -> bool:
        return True

    def print_row(self, pkt) -> None:
        """Print a single packet as JSON."""
        pkt_dict = _packet_to_dict(pkt)
        if not self._array_started:
            click.echo("[")
            self._array_started = True
            # First packet - no leading comma
            click.echo("  " + json.dumps(pkt_dict), nl=False)
        else:
            # Subsequent packets - leading comma
            click.echo(",")
            click.echo("  " + json.dumps(pkt_dict), nl=False)
        self._packet_count += 1

    def finalize(self) -> None:
        """Close the JSON array."""
        if self._array_started:
            click.echo("")  # Newline after last packet
            click.echo("]")
        else:
            # No packets received, output empty array
            click.echo("[]")


# Mapping of format names to streaming printer classes
_STREAMING_PRINTERS = {
    "tabular": _StreamingTablePrinter,
    "json": _StreamingJsonPrinter,
}


def _print_packets_tabular(pkts: List) -> None:
    """Print packets in a formatted table using tabulate."""
    if not pkts:
        click.echo("No packets!")
        return

    # For batch printing, use the full table format
    first_pkt = pkts[0]
    is_decrypted = isinstance(first_pkt, DecryptedPacket)
    has_real_location = not first_pkt.location.fake

    headers = ["TIMESTAMP", "TIME", "RSSI"]
    if is_decrypted:
        headers.extend(["COUNTER", "SEQ"])
    if has_real_location:
        headers.append("COORDINATES")
    if is_decrypted:
        headers.append("PAYLOAD")

    rows = []
    for pkt in pkts:
        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
        row = [pkt.timestamp, ts, pkt.rssi if pkt.rssi is not None else "None"]

        if is_decrypted:
            row.extend([pkt.counter, pkt.sequence])

        if has_real_location:
            loc = pkt.location
            row.append(f"{loc.lat:.6f},{loc.lon:.6f}")

        if is_decrypted:
            row.append(f'"{pkt.payload}"')

        rows.append(row)

    click.echo("\n" + tabulate(rows, headers=headers, tablefmt="grid"))


def _print_packets_csv(pkts) -> None:
    click.echo("timestamp, datetime, latitude, longitude, payload")
    for pkt in pkts:
        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
        if isinstance(pkt, DecryptedPacket):
            payload = pkt.payload
        elif isinstance(pkt, EncryptedPacket):
            payload = pkt.payload.hex()
        click.echo(
            f'{pkt.timestamp}, {ts}, {pkt.location.lat:.6f}, {pkt.location.lon:.6f}, "{payload}"'
        )


def _print_packets_json(pkts) -> None:
    """Print packets as a JSON array."""
    json_packets = [_packet_to_dict(pkt) for pkt in pkts]
    click.echo(json.dumps(json_packets, indent=2))


_OUTPUT_FORMATS = {
    "csv": "_print_packets_csv",
    "tabular": "_print_packets_tabular",
    "json": "_print_packets_json",
}


def _print_packets(pkts, output: str = "tabular") -> None:
    if not output:
        _print_packets_tabular(pkts)
        return

    format_key = output.lower().strip()
    if format_key in _OUTPUT_FORMATS:
        func = globals()[_OUTPUT_FORMATS[format_key]]
        func(pkts)
    else:
        _print_packets_tabular(pkts)


def _print_device(dev: Device) -> None:
    click.echo(f'id: "{dev.id}", ', nl=False)
    click.echo(f'name: "{dev.name}", ', nl=False)
    click.echo(f"tags: {str(dev.tags)}, ", nl=False)
    ts = datetime.fromtimestamp(dev.created_ts).strftime("%c")
    click.echo(f'created: "{ts}", ', nl=False)
    click.echo(f"active: {str(dev.active)}", nl=False)
    if dev.key:
        click.secho(f', key: "{dev.key}"')
    else:
        click.echo("")


def _get_version() -> str:
    """Return package version, with fallback for development installs."""
    try:
        from importlib.metadata import version

        return version("pyhubblenetwork")
    except Exception:
        return "dev"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=_get_version(), prog_name="hubblenetwork")
def cli() -> None:
    """Hubble SDK CLI."""
    # top-level group; subcommands are added below


@cli.command("validate-credentials")
@click.option(
    "--org-id",
    "-o",
    type=str,
    envvar="HUBBLE_ORG_ID",
    default=None,
    show_default=False,
    help="Organization ID (if not using HUBBLE_ORG_ID env var)",
)
@click.option(
    "--token",
    "-t",
    type=str,
    envvar="HUBBLE_API_TOKEN",
    default=None,
    show_default=False,
    help="Token (if not using HUBBLE_API_TOKEN env var)",
)
def validate_credentials(org_id, token) -> None:
    """Validate the given credentials"""
    # subgroup for organization-related commands
    credentials = cloud.Credentials(org_id, token)
    env = cloud.get_env_from_credentials(credentials)
    if env:
        click.echo(f'Valid credentials (env="{env.name}")')
    else:
        click.secho("Invalid credentials!", fg="red", err=True)


@cli.group()
def ble() -> None:
    """BLE utilities."""
    # subgroup for BLE-related commands


@ble.command("detect")
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=10,
    show_default=True,
    help="Timeout in seconds",
)
@click.option(
    "--key",
    "-k",
    required=True,
    type=str,
    default=None,
    show_default=False,
    help="Key to decrypt packets (base64 encoded, required)",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["json", "tabular"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Enable debug logging to stderr",
)
def ble_detect(
    timeout: Optional[int] = None,
    key: str = None,
    output_format: str = "tabular",
    debug: bool = False,
) -> None:
    """
    Scan for a single BLE packet and decrypt with key.

    This mode is designed for programmatic validation of BLE packets.
    The key parameter is required. Check the 'success' field in JSON output.

    Example:
      hubblenetwork ble detect --key "yourBase64Key=" --timeout 20
      hubblenetwork ble detect -k "key=" -o tabular
    """
    use_json = output_format.lower() == "json"

    # Set log level based on debug flag
    logger.setLevel(logging.DEBUG if debug else logging.WARNING)

    def _output_error(msg: str) -> None:
        if use_json:
            click.echo(json.dumps({"success": False, "error": msg}))
        else:
            click.secho(f"[ERROR] {msg}", fg="red", err=True)

    # Try to decode the base64 key
    try:
        decoded_key = bytearray(base64.b64decode(key))
        logger.debug("Key decoded successfully")
    except (binascii.Error, Exception) as e:
        logger.error(f"Base64 decoding failed: {e}")
        _output_error("Base64 decoding failed for provided key")
        return

    # Set up timeout tracking
    start = time.monotonic()
    deadline = None if timeout is None else start + timeout

    if timeout:
        logger.debug(f"Starting BLE scan with {timeout}s timeout")
    else:
        logger.debug("Starting BLE scan (no timeout)")

    # Continuously scan until we find a packet we can decrypt or timeout
    while deadline is None or time.monotonic() < deadline:
        this_timeout = None if deadline is None else max(deadline - time.monotonic(), 0)

        # Scan for a single packet
        try:
            pkt = ble_mod.scan_single(timeout=this_timeout)
        except Exception as e:
            logger.error(f"BLE scanning error: {e}")
            _output_error(f"BLE scanning error: {str(e)}")
            return

        # Check if packet was found
        if not pkt:
            # Timeout reached without finding any packet
            logger.error("Timeout: No BLE packets found")
            _output_error("No BLE packets found within timeout period")
            return

        logger.debug("Packet received, attempting decryption...")

        # Attempt to decrypt the packet
        decrypted_pkt = decrypt(decoded_key, pkt)

        if decrypted_pkt:
            # If we can decrypt it, output success
            datetime_str = datetime.fromtimestamp(decrypted_pkt.timestamp).strftime(
                "%c"
            )
            logger.info("Packet decrypted successfully!")

            if use_json:
                result = {
                    "success": True,
                    "packet": {
                        "datetime": datetime_str,
                        "rssi": decrypted_pkt.rssi,
                        "payload_bytes": len(decrypted_pkt.payload),
                    },
                }
                click.echo(json.dumps(result))
            else:
                click.secho("[SUCCESS] ", fg="green", nl=False)
                click.echo(
                    f"Packet decrypted: {datetime_str}, RSSI: {decrypted_pkt.rssi} dBm, {len(decrypted_pkt.payload)} bytes"
                )
            return

        logger.debug(
            "Decryption failed (doesn't match key), scanning for another packet..."
        )

    # If we exit the loop, it means we've exceeded the timeout without finding a valid packet
    _output_error("No valid packets found within timeout period")


@ble.command("scan")
@click.option(
    "--timeout",
    "-t",
    type=int,
    show_default=False,
    help="Timeout in seconds (default: no timeout)",
)
@click.option(
    "--count",
    "-n",
    type=int,
    default=None,
    show_default=False,
    help="Stop after receiving N packets",
)
@click.option(
    "--key",
    "-k",
    type=str,
    default=None,
    show_default=False,
    help="Attempt to decrypt any received packet with the given key",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=2,
    show_default=True,
    help="Number of days to check back when decrypting",
)
@click.option("--ingest", is_flag=True, help="Ingest packets to backend (requires key)")
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format for packets",
)
def ble_scan(
    timeout: Optional[int] = None,
    count: Optional[int] = None,
    ingest: bool = False,
    key: Optional[str] = None,
    days: int = 2,
    output_format: str = "tabular",
) -> None:
    """
    Scan for UUID 0xFCA6 and print packets as they are found.

    Example:
      hubblenetwork ble scan --timeout 30
      hubblenetwork ble scan --key "base64key=" --timeout 60
      hubblenetwork ble scan -o json --timeout 10
      hubblenetwork ble scan -n 5              # Stop after 5 packets
    """
    # Get the appropriate streaming printer
    printer_class = _STREAMING_PRINTERS.get(
        output_format.lower(), _StreamingTablePrinter
    )
    printer = printer_class()

    if not printer.suppress_info_messages:
        click.secho("[INFO] Scanning for Hubble devices... (Press Ctrl+C to stop)")

    if ingest:
        org = Organization(
            org_id=_get_env_or_fail("HUBBLE_ORG_ID"),
            api_token=_get_env_or_fail("HUBBLE_API_TOKEN"),
        )

    start = time.monotonic()
    deadline = None if timeout is None else start + timeout

    # Pre-decode the key if provided
    decoded_key: Optional[bytearray] = None
    if key:
        try:
            decoded_key = bytearray(base64.b64decode(key))
        except (binascii.Error, Exception) as e:
            if printer.suppress_info_messages:
                click.echo(json.dumps({"error": f"Invalid base64 key: {e}"}))
                return
            raise click.ClickException(f"Invalid base64 key: {e}")

    try:
        while deadline is None or time.monotonic() < deadline:
            # Check if we've hit the count limit
            if count is not None and printer.packet_count >= count:
                break

            this_timeout = (
                None if deadline is None else max(deadline - time.monotonic(), 0)
            )

            pkt = ble_mod.scan_single(timeout=this_timeout)
            if not pkt:
                break

            # If we have a key, attempt to decrypt
            if decoded_key:
                decrypted_pkt = decrypt(decoded_key, pkt, days=days)
                if decrypted_pkt:
                    printer.print_row(decrypted_pkt)
                    # We only allow ingestion of packets you know the key of
                    # so we don't ingest bogus data in the backend
                    if ingest:
                        org.ingest_packet(pkt)
            else:
                printer.print_row(pkt)
    except KeyboardInterrupt:
        pass  # Just exit the loop, cleanup happens below
    finally:
        # Allow printer to finalize (e.g., close JSON array)
        printer.finalize()

        if not printer.suppress_info_messages:
            click.echo("")  # New line after ^C or completion
            click.secho(
                f"[INFO] Scanning stopped. {printer.packet_count} packet(s) received.",
                fg="yellow",
            )


@ble.command("check-time")
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=None,
    show_default=False,
    help="Timeout in seconds (default: no timeout)",
)
@click.option(
    "--key",
    "-k",
    required=True,
    type=str,
    help="Key for checking time counter (base64 encoded)",
)
@click.option(
    "--json-output",
    "-j",
    is_flag=True,
    default=False,
    help="Output results as JSON",
)
def ble_check_time(
    timeout: Optional[int] = None, key: str = None, json_output: bool = False
) -> int:
    """
    Scan for BLE packets and check if the device's UTC time is out of spec.

    For each received packet, attempts to find the time counter delta using the
    provided key. Reports how many days off the device time is from the expected
    value (0 = correct, negative = behind, positive = ahead).

    A device is considered out of spec if it is more than 2 days off.

    Example:
      hubblenetwork ble check-time --key "yourBase64Key=" --timeout 30
    """
    # Decode the key
    try:
        decoded_key = bytearray(base64.b64decode(key))
    except (binascii.Error, Exception) as e:
        if json_output:
            click.echo(json.dumps({"error": f"Base64 decoding failed: {e}"}))
        else:
            click.secho(
                f"[ERROR] Base64 decoding failed for provided key: {e}",
                fg="red",
                err=True,
            )
        return

    if not json_output:
        click.secho("[INFO] Scanning for Hubble devices to check time sync...")

    start = time.monotonic()
    deadline = None if timeout is None else start + timeout

    while deadline is None or time.monotonic() < deadline:
        this_timeout = None if deadline is None else max(deadline - time.monotonic(), 0)

        pkt = ble_mod.scan_single(timeout=this_timeout)
        if not pkt:
            break

        # Check which time counter the packet resolves for
        delta = find_time_counter_delta(decoded_key, pkt)

        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")

        if delta is None:
            # Could not resolve the packet with this key
            if not json_output:
                click.echo(
                    f"{ts}  RSSI: {pkt.rssi} dBm  - Could not resolve packet with provided key"
                )
        else:
            # Packet resolved - report the delta
            if delta == 0:
                status = "Device time is correct"
                in_spec = True
            elif delta > 0:
                status = (
                    f"Device time is {delta} day{'s' if abs(delta) != 1 else ''} ahead"
                )
                in_spec = abs(delta) <= 2
            else:
                status = f"Device time is {abs(delta)} day{'s' if abs(delta) != 1 else ''} behind"
                in_spec = abs(delta) <= 2

            if json_output:
                click.echo(
                    json.dumps(
                        {
                            "resolved": True,
                            "delta_days": delta,
                            "in_spec": in_spec,
                            "rssi": pkt.rssi,
                            "timestamp": ts,
                        }
                    )
                )
            else:
                color = "green" if in_spec else "red"
                spec_label = "" if in_spec else " [OUT OF SPEC]"
                click.echo(f"{ts}  RSSI: {pkt.rssi} dBm  - ", nl=False)
                click.secho(f"{status}{spec_label}", fg=color)
            return 0

    if json_output:
        click.echo(json.dumps({"resolved": False}))
    else:
        click.secho(
            "[ERROR] No valid packets found within timeout period", fg="red", err=True
        )
    return -1


@cli.group()
def ready() -> None:
    """Hubble Ready device provisioning utilities."""


@ready.command("scan")
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=10.0,
    show_default=True,
    help="Scan timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_scan(timeout: float = 10.0, output_format: str = "tabular") -> None:
    """
    Scan for Hubble Ready devices advertising 0xFCA7.

    Discovers devices that are ready for provisioning and displays them
    in a table with their name, address, and signal strength.

    Example:
      hubblenetwork ready scan
      hubblenetwork ready scan --timeout 20
      hubblenetwork ready scan --format json
    """
    use_json = output_format.lower() == "json"
    devices_found: List[ready_mod.HubbleReadyDevice] = []
    device_count = 0
    header_printed = False

    # Column widths for consistent formatting
    col_widths = {"num": 3, "name": 20, "address": 17, "rssi": 6}

    def make_separator() -> str:
        return (
            f"+{'-' * (col_widths['num'] + 2)}"
            f"+{'-' * (col_widths['name'] + 2)}"
            f"+{'-' * (col_widths['address'] + 2)}"
            f"+{'-' * (col_widths['rssi'] + 2)}+"
        )

    def format_row(num: str, name: str, address: str, rssi: str) -> str:
        return (
            f"| {num:<{col_widths['num']}} "
            f"| {name:<{col_widths['name']}} "
            f"| {address:<{col_widths['address']}} "
            f"| {rssi:<{col_widths['rssi']}} |"
        )

    def on_device(dev: ready_mod.HubbleReadyDevice) -> None:
        nonlocal device_count, header_printed
        device_count += 1
        devices_found.append(dev)

        if use_json:
            return

        if not header_printed:
            click.echo("")
            click.echo(make_separator())
            click.secho(format_row("#", "NAME", "ADDRESS", "RSSI"), bold=True)
            click.echo(make_separator())
            header_printed = True

        name = (dev.name or "(unknown)")[:col_widths["name"]]
        click.echo(format_row(str(device_count), name, dev.address, str(dev.rssi)))
        click.echo(make_separator())

    if not use_json:
        click.secho("Scanning for Hubble Ready devices... (Press Ctrl+C to stop)")

    try:
        ready_mod.scan_ready_devices_streaming(timeout=timeout, on_device=on_device)
    except KeyboardInterrupt:
        pass

    if use_json:
        json_output = [
            {"name": d.name, "address": d.address, "rssi": d.rssi}
            for d in devices_found
        ]
        click.echo(json.dumps(json_output, indent=2))
        return

    if not devices_found:
        click.echo("\nNo Hubble Ready devices found.")
        return

    click.echo(f"\nFound {device_count} device(s)")


pass_orgcfg = click.make_pass_decorator(Organization, ensure=True)


@cli.group()
@click.option(
    "--org-id",
    "-o",
    type=str,
    envvar="HUBBLE_ORG_ID",
    default=None,
    show_default=False,
    help="Organization ID (if not using HUBBLE_ORG_ID env var)",
)
@click.option(
    "--token",
    "-t",
    type=str,
    envvar="HUBBLE_API_TOKEN",
    default=None,
    show_default=False,
    help="Token (if not using HUBBLE_API_TOKEN env var)",
)
@click.pass_context
def org(ctx, org_id, token) -> None:
    """Organization utilities."""
    # subgroup for organization-related commands
    try:
        ctx.obj = Organization(org_id=org_id, api_token=token)
    except InvalidCredentialsError as e:
        raise click.BadParameter(str(e))


@org.command("info")
@pass_orgcfg
def info(org: Organization) -> None:
    click.echo("Organization info:")
    click.echo(f"\tID:   {org.org_id}")
    click.echo(f"\tName: {org.name}")
    click.echo(f"\tEnv:  {org.env}")


@org.command("list-devices")
@pass_orgcfg
def list_devices(org: Organization) -> None:
    devices = org.list_devices()
    for device in devices:
        _print_device(device)


@org.command("register-device")
@click.option(
    "--encryption",
    "-e",
    type=str,
    default=None,
    show_default=False,  # show default in --help
    help="Encryption type [AES-256-CTR, AES-128-CTR]",
)
@pass_orgcfg
def register_device(org: Organization, encryption) -> None:
    if encryption:
        click.secho(f'[INFO] Overriding default encryption, using "{encryption}"')
    click.secho(str(org.register_device(encryption=encryption)))


@org.command("set-device-name")
@click.argument("device-id", type=str)
@click.argument("name", type=str)
@pass_orgcfg
def set_device_name(org: Organization, device_id: str, name: str) -> None:
    click.secho(str(org.set_device_name(device_id, name)))


@org.command("get-packets")
@click.argument("device-id", type=str)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "csv", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format for packets",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=7,
    show_default=True,
    help="Number of days to query back (from now)",
)
@pass_orgcfg
def get_packets(
    org: Organization, device_id: str, output_format: str = "tabular", days: int = 7
) -> None:
    """
    Retrieve and display packets for a device.

    Example:
      hubblenetwork org get-packets DEVICE_ID
      hubblenetwork org get-packets DEVICE_ID -o json
      hubblenetwork org get-packets DEVICE_ID --format csv --days 30
    """
    device = Device(id=device_id)
    packets = org.retrieve_packets(device, days=days)
    _print_packets(packets, output_format)


def main(argv: Optional[list[str]] = None) -> int:
    """
    Entry point used by console_scripts.

    Returns a process exit code instead of letting Click call sys.exit for easier testing.
    """
    try:
        # standalone_mode=False prevents Click from calling sys.exit itself.
        cli.main(args=argv, prog_name="hubblenetwork", standalone_mode=False)
    except SystemExit as e:
        return int(e.code)
    except Exception as e:  # safety net to avoid tracebacks in user CLI
        click.secho(f"Unexpected error: {e}", fg="red", err=True)
        return 2
    return 0


if __name__ == "__main__":
    # Forward command-line args (excluding the program name) to main()
    raise SystemExit(main())
