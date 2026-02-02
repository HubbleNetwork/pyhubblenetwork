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


def _format_ready_json_success(
    command: str,
    device_address: str,
    result: dict,
    duration_ms: int,
    device_name: Optional[str] = None,
) -> dict:
    """
    Format a successful ready command result as JSON.

    Standard structure:
    {
        "success": true,
        "command": "ready scan",
        "device": {"address": "AA:BB:CC:DD:EE:FF", "name": "Device Name"},
        "result": {...},
        "duration_ms": 1234
    }
    """
    device_obj = {"address": device_address}
    if device_name is not None:
        device_obj["name"] = device_name

    return {
        "success": True,
        "command": command,
        "device": device_obj,
        "result": result,
        "duration_ms": duration_ms,
    }


def _format_ready_json_error(
    command: str,
    device_address: str,
    error: Exception,
    duration_ms: int,
    device_name: Optional[str] = None,
) -> dict:
    """
    Format a failed ready command result as JSON.

    Standard structure:
    {
        "success": false,
        "command": "ready info",
        "device": {"address": "AA:BB:CC:DD:EE:FF"},
        "error": {
            "code": "BleError",
            "name": "Invalid Attribute Value Length",
            "message": "Connection failed: ..."
        },
        "duration_ms": 1234
    }

    For BleError exceptions with ATT error codes, includes code and name fields.
    """
    from hubblenetwork.errors import BleError

    device_obj = {"address": device_address}
    if device_name is not None:
        device_obj["name"] = device_name

    error_obj = {
        "code": type(error).__name__,
        "message": str(error),
    }

    # If it's a BleError with ATT error code, include structured error info
    if isinstance(error, BleError) and error.att_error_code is not None:
        ble_dict = error.to_dict()
        error_obj["name"] = ble_dict.get("att_error_name", "")
        error_obj["att_error_code"] = ble_dict.get("att_error_code")

    return {
        "success": False,
        "command": command,
        "device": device_obj,
        "error": error_obj,
        "duration_ms": duration_ms,
    }


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
@click.option(
    "--address",
    "-a",
    type=str,
    default=None,
    help="Filter results to specific device MAC address",
)
def ready_scan(timeout: float = 10.0, output_format: str = "tabular", address: Optional[str] = None) -> None:
    """
    Scan for Hubble Ready devices advertising 0xFCA7.

    Discovers devices that are ready for provisioning and displays them
    in a table with their name, address, and signal strength.

    Example:
      hubblenetwork ready scan
      hubblenetwork ready scan --timeout 20
      hubblenetwork ready scan --format json
      hubblenetwork ready scan --address AA:BB:CC:DD:EE:FF
    """
    use_json = output_format.lower() == "json"
    devices_found: List[ready_mod.HubbleReadyDevice] = []
    device_count = 0
    header_printed = False
    start_time = time.monotonic()

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

        # Filter by address if specified (case-insensitive)
        if address is not None and dev.address.lower() != address.lower():
            return

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

    error_occurred = None
    try:
        ready_mod.scan_ready_devices_streaming(timeout=timeout, on_device=on_device)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        error_occurred = e

    duration_ms = int((time.monotonic() - start_time) * 1000)

    if use_json:
        if error_occurred:
            # For scan errors, we don't have a specific device
            json_output = _format_ready_json_error(
                command="ready scan",
                device_address="",
                error=error_occurred,
                duration_ms=duration_ms,
            )
        else:
            # Success case - return list of devices in result
            devices_list = [
                {"name": d.name, "address": d.address, "rssi": d.rssi}
                for d in devices_found
            ]
            json_output = {
                "success": True,
                "command": "ready scan",
                "result": {
                    "devices": devices_list,
                    "count": len(devices_list),
                },
                "duration_ms": duration_ms,
            }
        click.echo(json.dumps(json_output, indent=2))
        if error_occurred:
            sys.exit(2)
        return

    if error_occurred:
        click.secho(f"\n[ERROR] Scan failed: {error_occurred}", fg="red", err=True)
        sys.exit(2)

    if not devices_found:
        click.echo("\nNo Hubble Ready devices found.")
        return

    click.echo(f"\nFound {device_count} device(s)")


def _select_ready_device(
    devices: List[ready_mod.HubbleReadyDevice],
) -> Optional[ready_mod.HubbleReadyDevice]:
    """Present interactive device selection using questionary."""
    import questionary

    if not devices:
        return None

    choices = [
        questionary.Choice(
            title=f"{d.name or 'Unknown'} ({d.address}) [{d.rssi} dBm]",
            value=d,
        )
        for d in devices
    ]

    return questionary.select("Select a device:", choices=choices).ask()


@ready.command("info")
@click.option(
    "--address",
    "-a",
    type=str,
    default=None,
    help="Device MAC address (skip scan and connect directly)",
)
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
def ready_info(
    address: Optional[str] = None, timeout: float = 10.0, output_format: str = "tabular"
) -> None:
    """
    Connect to a Hubble Ready device and show characteristics.

    Scans for devices, lets you select one interactively, then connects
    and displays all Hubble Provisioning Service characteristics with
    parsed values.

    If --address is provided, skips scanning and connects directly.

    Example:
      hubblenetwork ready info
      hubblenetwork ready info --timeout 15
      hubblenetwork ready info --format json
      hubblenetwork ready info --address AA:BB:CC:DD:EE:FF --format json
    """
    use_json = output_format.lower() == "json"

    # If address provided, connect directly
    if address:
        if not use_json:
            click.echo(f"Connecting to {address}...")

        start_time = time.monotonic()
        try:
            characteristics = ready_mod.connect_and_read_characteristics(
                address, timeout=timeout
            )
            duration_ms = int((time.monotonic() - start_time) * 1000)
        except Exception as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            if use_json:
                json_output = _format_ready_json_error(
                    command="ready info",
                    device_address=address,
                    error=e,
                    duration_ms=duration_ms,
                )
                click.echo(json.dumps(json_output, indent=2))
            else:
                click.secho(f"\n[ERROR] Connection failed: {e}", fg="red", err=True)
            sys.exit(2)

        if use_json:
            characteristics_list = [
                {
                    "name": c.name,
                    "uuid": c.uuid,
                    "raw_hex": c.raw_value.hex() if c.raw_value else None,
                    "value": c.parsed_value,
                }
                for c in characteristics
            ]
            json_output = _format_ready_json_success(
                command="ready info",
                device_address=address,
                result={"characteristics": characteristics_list},
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(json_output, indent=2))
            return

        # Build table for display
        headers = ["CHARACTERISTIC", "UUID", "VALUE"]
        rows = []
        for char in characteristics:
            # Handle multi-line values
            value = char.parsed_value or "(empty)"
            rows.append([char.name, char.uuid, value])

        click.echo("")
        click.echo(tabulate(rows, headers=headers, tablefmt="grid"))
        return

    # Original scan + selection flow
    if not use_json:
        click.secho("Scanning for Hubble Ready devices...")

    start_time = time.monotonic()
    devices = ready_mod.scan_ready_devices(timeout=timeout)

    if not devices:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if use_json:
            # No devices found - not an error, but no success either
            json_output = {
                "success": False,
                "command": "ready info",
                "error": {
                    "code": "NoDevicesFound",
                    "message": "No Hubble Ready devices found",
                },
                "duration_ms": duration_ms,
            }
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.echo("\nNo Hubble Ready devices found.")
        return

    if not use_json:
        click.echo(f"\nFound {len(devices)} device(s):\n")

    # Interactive device selection
    selected = _select_ready_device(devices)
    if selected is None:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if not use_json:
            click.echo("No device selected.")
        return

    if not use_json:
        click.echo(f"\nConnecting to {selected.address}...")

    try:
        characteristics = ready_mod.connect_and_read_characteristics(selected.address, timeout=timeout)
        duration_ms = int((time.monotonic() - start_time) * 1000)
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if use_json:
            json_output = _format_ready_json_error(
                command="ready info",
                device_address=selected.address,
                error=e,
                duration_ms=duration_ms,
                device_name=selected.name,
            )
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"\n[ERROR] Connection failed: {e}", fg="red", err=True)
        sys.exit(2)

    if use_json:
        characteristics_list = [
            {
                "name": c.name,
                "uuid": c.uuid,
                "raw_hex": c.raw_value.hex() if c.raw_value else None,
                "value": c.parsed_value,
            }
            for c in characteristics
        ]
        json_output = _format_ready_json_success(
            command="ready info",
            device_address=selected.address,
            result={"characteristics": characteristics_list},
            duration_ms=duration_ms,
            device_name=selected.name,
        )
        click.echo(json.dumps(json_output, indent=2))
        return

    # Build table for display
    headers = ["CHARACTERISTIC", "UUID", "VALUE"]
    rows = []
    for char in characteristics:
        # Handle multi-line values
        value = char.parsed_value or "(empty)"
        rows.append([char.name, char.uuid, value])

    click.echo("")
    click.echo(tabulate(rows, headers=headers, tablefmt="grid"))


@ready.command("read-status")
@click.option(
    "--address",
    "-a",
    type=str,
    required=True,
    help="Device MAC address",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
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
def ready_read_status(
    address: str, timeout: float = 30.0, output_format: str = "tabular"
) -> None:
    """
    Read the Status characteristic from a Hubble Ready device.

    Connects to the device and reads the Status characteristic (0x0001),
    which contains version information and provisioning flags.

    Example:
      hubblenetwork ready read-status --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready read-status -a AA:BB:CC:DD:EE:FF --format json
    """
    use_json = output_format.lower() == "json"

    if not use_json:
        click.echo(f"Connecting to {address}...")

    start_time = time.monotonic()
    try:
        status = ready_mod.read_status(address, timeout=timeout)
        duration_ms = int((time.monotonic() - start_time) * 1000)
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if use_json:
            json_output = _format_ready_json_error(
                command="ready read-status",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"\n[ERROR] Connection failed: {e}", fg="red", err=True)
        sys.exit(2)

    if use_json:
        result = {
            "version": {
                "major": status.version_major,
                "minor": status.version_minor,
                "patch": status.version_patch,
                "string": status.version_string,
            },
            "mode": status.mode_string,
            "is_locked": status.is_locked,
            "flags": {
                "key_written": status.key_written,
                "config_written": status.config_written,
                "epoch_time_written": status.epoch_time_written,
            },
        }
        json_output = _format_ready_json_success(
            command="ready read-status",
            device_address=address,
            result=result,
            duration_ms=duration_ms,
        )
        click.echo(json.dumps(json_output, indent=2))
        return

    # Tabular output
    click.echo("")
    click.secho("Status Characteristic", bold=True)
    click.echo("")
    click.echo(f"  Version:       {status.version_string}")
    click.echo(f"  Mode:          {status.mode_string}")
    click.echo("")
    click.secho("  Provisioning Flags:", bold=True)
    click.echo(f"    Key:         {'Yes' if status.key_written else 'No'}")
    click.echo(f"    Config:      {'Yes' if status.config_written else 'No'}")
    click.echo(f"    Time:        {'Yes' if status.epoch_time_written else 'No'}")


@ready.command("read-key-info")
@click.option(
    "--address",
    "-a",
    type=str,
    required=True,
    help="Device MAC address",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
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
def ready_read_key_info(
    address: str, timeout: float = 30.0, output_format: str = "tabular"
) -> None:
    """
    Read the Device Key characteristic from a Hubble Ready device.

    Connects to the device and reads the Device Key characteristic (0x0003),
    which contains encryption mode information.

    Example:
      hubblenetwork ready read-key-info --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready read-key-info -a AA:BB:CC:DD:EE:FF --format json
    """
    use_json = output_format.lower() == "json"

    if not use_json:
        click.echo(f"Connecting to {address}...")

    start_time = time.monotonic()
    try:
        key_info = ready_mod.read_key_info(address, timeout=timeout)
        duration_ms = int((time.monotonic() - start_time) * 1000)
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if use_json:
            json_output = _format_ready_json_error(
                command="ready read-key-info",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"\n[ERROR] Connection failed: {e}", fg="red", err=True)
        sys.exit(2)

    if use_json:
        result = {
            "encryption_mode": key_info.encryption_mode,
            "encryption_mode_code": key_info.encryption_mode_code,
            "key_size_bytes": key_info.key_size,
        }
        json_output = _format_ready_json_success(
            command="ready read-key-info",
            device_address=address,
            result=result,
            duration_ms=duration_ms,
        )
        click.echo(json.dumps(json_output, indent=2))
        return

    # Tabular output
    click.echo("")
    click.secho("Device Key Characteristic", bold=True)
    click.echo("")
    click.echo(f"  Encryption Mode:  {key_info.encryption_mode}")
    click.echo(f"  Key Size:         {key_info.key_size} bytes")


@ready.command("read-config")
@click.option(
    "--address",
    "-a",
    type=str,
    required=True,
    help="Device MAC address",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
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
def ready_read_config(
    address: str, timeout: float = 30.0, output_format: str = "tabular"
) -> None:
    """
    Read the Device Configuration characteristic from a Hubble Ready device.

    Connects to the device and reads the Device Configuration characteristic (0x0004),
    which contains EID type, rotation period, and pool size settings.

    Example:
      hubblenetwork ready read-config --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready read-config -a AA:BB:CC:DD:EE:FF --format json
    """
    use_json = output_format.lower() == "json"

    if not use_json:
        click.echo(f"Connecting to {address}...")

    start_time = time.monotonic()
    try:
        config = ready_mod.read_config(address, timeout=timeout)
        duration_ms = int((time.monotonic() - start_time) * 1000)
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if use_json:
            json_output = _format_ready_json_error(
                command="ready read-config",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"\n[ERROR] Connection failed: {e}", fg="red", err=True)
        sys.exit(2)

    if use_json:
        result = {
            "eid_type": config.eid_type,
            "eid_type_code": config.eid_type_code,
            "rotation_period_seconds": config.rotation_period,
            "pool_size": config.pool_size,
            "raw_bytes": config.raw_bytes,
        }
        json_output = _format_ready_json_success(
            command="ready read-config",
            device_address=address,
            result=result,
            duration_ms=duration_ms,
        )
        click.echo(json.dumps(json_output, indent=2))
        return

    # Tabular output
    click.echo("")
    click.secho("Device Configuration Characteristic", bold=True)
    click.echo("")
    click.echo(f"  {config.to_display_string()}")


@ready.command("read-time")
@click.option(
    "--address",
    "-a",
    required=True,
    help="BLE address of the device (e.g., AA:BB:CC:DD:EE:FF)",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
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
def ready_read_time(
    address: str, timeout: float = 30.0, output_format: str = "tabular"
) -> None:
    """
    Read the Epoch Time characteristic from a Hubble Ready device.

    Connects to the device and reads the Epoch Time characteristic (0x0005),
    which contains the device's current Unix timestamp.

    Example:
      hubblenetwork ready read-time --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready read-time -a AA:BB:CC:DD:EE:FF --format json
    """
    use_json = output_format.lower() == "json"

    if not use_json:
        click.echo(f"Connecting to {address}...")

    start_time = time.monotonic()
    try:
        timestamp = ready_mod.read_time(address, timeout=timeout)
        duration_ms = int((time.monotonic() - start_time) * 1000)
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if use_json:
            json_output = _format_ready_json_error(
                command="ready read-time",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"\n[ERROR] Connection failed: {e}", fg="red", err=True)
        sys.exit(2)

    if use_json:
        timestamp_iso = datetime.fromtimestamp(timestamp).isoformat()
        result = {
            "timestamp": timestamp,
            "timestamp_iso": timestamp_iso,
        }
        json_output = _format_ready_json_success(
            command="ready read-time",
            device_address=address,
            result=result,
            duration_ms=duration_ms,
        )
        click.echo(json.dumps(json_output, indent=2))
        return

    # Tabular output
    click.echo("")
    click.secho("Epoch Time Characteristic", bold=True)
    click.echo("")
    timestamp_iso = datetime.fromtimestamp(timestamp).isoformat()
    timestamp_human = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S %Z")
    click.echo(f"  Unix Timestamp: {timestamp}")
    click.echo(f"  ISO 8601:       {timestamp_iso}")
    click.echo(f"  Human:          {timestamp_human}")


@ready.command("write-key")
@click.option(
    "--address",
    "-a",
    required=True,
    help="BLE address of the device (e.g., AA:BB:CC:DD:EE:FF)",
)
@click.option(
    "--key",
    "-k",
    required=True,
    help="Base64-encoded encryption key (16 bytes for AES-128-CTR, 32 bytes for AES-256-CTR)",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
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
def ready_write_key(
    address: str, key: str, timeout: float = 30.0, output_format: str = "tabular"
) -> None:
    """
    Write an encryption key to the Device Key characteristic.

    This command reads the device's encryption mode first to validate that
    the key length matches the expected size (16 bytes for AES-128-CTR,
    32 bytes for AES-256-CTR).

    Example:
      hubblenetwork ready write-key --address AA:BB:CC:DD:EE:FF --key <base64-key>
      hubblenetwork ready write-key -a AA:BB:CC:DD:EE:FF -k <base64-key> --format json
    """
    use_json = output_format.lower() == "json"

    # Decode the base64 key
    try:
        key_bytes = base64.b64decode(key)
    except Exception as e:
        if use_json:
            json_output = _format_ready_json_error(
                command="ready write-key",
                device_address=address,
                error=Exception(f"Invalid base64 key: {e}"),
                duration_ms=0,
            )
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"[ERROR] Invalid base64 key: {e}", fg="red", err=True)
        sys.exit(1)

    if not use_json:
        click.echo(f"Connecting to {address}...")

    start_time = time.monotonic()
    try:
        result = ready_mod.write_key(address, key_bytes, timeout=timeout)
        duration_ms = int((time.monotonic() - start_time) * 1000)
    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if use_json:
            json_output = _format_ready_json_error(
                command="ready write-key",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"\n[ERROR] Connection failed: {e}", fg="red", err=True)
        sys.exit(2)

    # Check if write was successful
    if not result.success:
        duration_ms = result.duration_ms
        if use_json:
            result_dict = result.to_dict()
            result_dict["key_size_bytes"] = len(key_bytes)
            json_output = {
                "success": False,
                "command": "ready write-key",
                "device": {"address": address},
                "error": {
                    "code": "WriteError",
                    "message": result.error_message or "Write operation failed",
                    "att_error_code": result.error_code,
                },
                "result": result_dict,
                "duration_ms": duration_ms,
            }
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"\n[ERROR] Write failed: {result.error_message}", fg="red", err=True)
        sys.exit(1)

    # Success case
    if use_json:
        result_dict = {
            "key_written": True,
            "key_size_bytes": len(key_bytes),
        }
        json_output = _format_ready_json_success(
            command="ready write-key",
            device_address=address,
            result=result_dict,
            duration_ms=duration_ms,
        )
        click.echo(json.dumps(json_output, indent=2))
        return

    # Tabular output
    click.echo("")
    click.secho("Device Key Write Successful", bold=True)
    click.echo("")
    click.echo(f"  Key size: {len(key_bytes)} bytes")
    click.echo(f"  Duration: {duration_ms} ms")


@ready.command("write-config")
@click.option(
    "--address",
    "-a",
    required=True,
    help="BLE address of the device (e.g., AA:BB:CC:DD:EE:FF)",
)
@click.option(
    "--eid-type",
    required=True,
    type=click.Choice(["utc", "counter"], case_sensitive=False),
    help="EID type: 'utc' for UTC-based or 'counter' for counter-based",
)
@click.option(
    "--pool-size",
    type=int,
    help="Pool size for counter mode (1-65535, required for counter mode)",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["json", "table"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format",
)
def ready_write_config(address: str, eid_type: str, pool_size: Optional[int], timeout: float, output_format: str):
    """Write device configuration (EID type, pool size) to a Hubble Ready device.

    This command validates configuration parameters locally and writes them to the
    Device Configuration characteristic.

    Examples:
      hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type utc
      hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type counter --pool-size 100
    """
    import time
    import sys
    from .ready import write_config
    from .errors import BleError

    start_time = time.monotonic()

    # Validate that pool_size is provided for counter mode
    if eid_type.lower() == "counter":
        if pool_size is None:
            if output_format == "json":
                error_obj = {
                    "success": False,
                    "command": "write-config",
                    "device": {"address": address},
                    "error": {
                        "code": "ValidationError",
                        "message": "--pool-size is required for counter mode",
                    },
                    "duration_ms": 0,
                }
                click.echo(json.dumps(error_obj, indent=2))
            else:
                click.echo("Error: --pool-size is required for counter mode", err=True)
            sys.exit(1)
    else:
        # UTC mode - pool_size will be ignored
        pool_size = 0

    try:
        result = write_config(address, eid_type, pool_size, rotation_period=0, timeout=timeout)
        duration_ms = int((time.monotonic() - start_time) * 1000)

        if result.success:
            # Success
            if output_format == "json":
                success_result = {
                    "config_written": True,
                    "eid_type": eid_type.lower(),
                    "rotation_period": 0,
                }
                if eid_type.lower() == "counter":
                    success_result["pool_size"] = pool_size

                success_obj = _format_ready_json_success(
                    command="write-config",
                    device_address=address,
                    result=success_result,
                    duration_ms=duration_ms,
                )
                click.echo(json.dumps(success_obj, indent=2))
            else:
                click.secho("✓ Configuration written successfully", fg="green", bold=True)
                click.echo("")
                click.echo(f"  EID type: {eid_type.lower()}")
                click.echo("  Rotation period: 0 seconds")
                if eid_type.lower() == "counter":
                    click.echo(f"  Pool size: {pool_size}")
                click.echo("")
                click.echo(f"  Duration: {duration_ms} ms")
            sys.exit(0)
        else:
            # Write validation failure
            if output_format == "json":
                result_dict = result.to_dict()
                result_dict["config_written"] = False
                error_dict = {
                    "code": "WriteError",
                    "message": result.error_message or "Configuration write failed",
                }
                if result.error_code is not None:
                    error_dict["att_error_code"] = result.error_code
                    from .errors import ATT_ERROR_NAMES
                    error_dict["att_error_name"] = ATT_ERROR_NAMES.get(
                        result.error_code,
                        f"Unknown ATT Error (0x{result.error_code:02X})"
                    )
                error_obj = {
                    "success": False,
                    "command": "write-config",
                    "device": {"address": address},
                    "error": error_dict,
                    "result": result_dict,
                    "duration_ms": duration_ms,
                }
                click.echo(json.dumps(error_obj, indent=2))
            else:
                click.secho("✗ Configuration write failed", fg="red", bold=True, err=True)
                if result.error_message:
                    click.echo(f"  {result.error_message}", err=True)
                if result.error_code is not None:
                    from .errors import ATT_ERROR_NAMES
                    error_name = ATT_ERROR_NAMES.get(
                        result.error_code,
                        f"Unknown ATT Error (0x{result.error_code:02X})"
                    )
                    click.echo(f"  ATT Error: 0x{result.error_code:02X} ({error_name})", err=True)
            sys.exit(1)

    except BleError as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if output_format == "json":
            error_obj = _format_ready_json_error(
                command="write-config",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(error_obj, indent=2))
        else:
            click.secho(f"✗ BLE Error: {e}", fg="red", bold=True, err=True)
        sys.exit(2)

    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if output_format == "json":
            error_obj = _format_ready_json_error(
                command="write-config",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(error_obj, indent=2))
        else:
            click.secho(f"✗ Error: {e}", fg="red", bold=True, err=True)
        sys.exit(2)


@ready.command("write-time")
@click.option(
    "--address",
    "-a",
    required=True,
    help="BLE address of the device (e.g., AA:BB:CC:DD:EE:FF)",
)
@click.option(
    "--timestamp",
    type=int,
    help="Unix timestamp (seconds since epoch). If not provided, uses current time.",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["json", "table"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format",
)
def ready_write_time(address: str, timestamp: Optional[int], timeout: float, output_format: str):
    """Write epoch time to a Hubble Ready device.

    This command writes a Unix timestamp to the Epoch Time characteristic.
    If no timestamp is provided, the current time is used.

    Examples:
      hubblenetwork ready write-time --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready write-time --address AA:BB:CC:DD:EE:FF --timestamp 1735603200
    """
    import time
    import sys
    from datetime import datetime, timezone
    from .ready import write_time
    from .errors import BleError

    start_time = time.monotonic()

    # Use current time if not provided
    actual_timestamp = timestamp if timestamp is not None else int(time.time())

    try:
        result = write_time(address, actual_timestamp, timeout=timeout)
        duration_ms = int((time.monotonic() - start_time) * 1000)

        if result.success:
            # Success
            if output_format == "json":
                success_result = {
                    "time_written": True,
                    "timestamp": actual_timestamp,
                    "timestamp_iso": datetime.fromtimestamp(actual_timestamp, tz=timezone.utc).isoformat(),
                }

                success_obj = _format_ready_json_success(
                    command="write-time",
                    device_address=address,
                    result=success_result,
                    duration_ms=duration_ms,
                )
                click.echo(json.dumps(success_obj, indent=2))
            else:
                click.secho("✓ Time written successfully", fg="green", bold=True)
                click.echo("")
                click.echo(f"  Timestamp: {actual_timestamp}")
                click.echo(f"  ISO 8601: {datetime.fromtimestamp(actual_timestamp, tz=timezone.utc).isoformat()}")
                click.echo(f"  Human readable: {datetime.fromtimestamp(actual_timestamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
                click.echo("")
                click.echo(f"  Duration: {duration_ms} ms")
            sys.exit(0)
        else:
            # Write failure
            if output_format == "json":
                result_dict = result.to_dict()
                result_dict["time_written"] = False
                error_dict = {
                    "code": "WriteError",
                    "message": result.error_message or "Time write failed",
                }
                if result.error_code is not None:
                    error_dict["att_error_code"] = result.error_code
                    from .errors import ATT_ERROR_NAMES
                    error_dict["att_error_name"] = ATT_ERROR_NAMES.get(
                        result.error_code,
                        f"Unknown ATT Error (0x{result.error_code:02X})"
                    )
                error_obj = {
                    "success": False,
                    "command": "write-time",
                    "device": {"address": address},
                    "error": error_dict,
                    "result": result_dict,
                    "duration_ms": duration_ms,
                }
                click.echo(json.dumps(error_obj, indent=2))
            else:
                click.secho("✗ Time write failed", fg="red", bold=True, err=True)
                if result.error_message:
                    click.echo(f"  {result.error_message}", err=True)
                if result.error_code is not None:
                    from .errors import ATT_ERROR_NAMES
                    error_name = ATT_ERROR_NAMES.get(
                        result.error_code,
                        f"Unknown ATT Error (0x{result.error_code:02X})"
                    )
                    click.echo(f"  ATT Error: 0x{result.error_code:02X} ({error_name})", err=True)
            sys.exit(1)

    except BleError as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if output_format == "json":
            error_obj = _format_ready_json_error(
                command="write-time",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(error_obj, indent=2))
        else:
            click.secho(f"✗ BLE Error: {e}", fg="red", bold=True, err=True)
        sys.exit(2)

    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        if output_format == "json":
            error_obj = _format_ready_json_error(
                command="write-time",
                device_address=address,
                error=e,
                duration_ms=duration_ms,
            )
            click.echo(json.dumps(error_obj, indent=2))
        else:
            click.secho(f"✗ Error: {e}", fg="red", bold=True, err=True)
        sys.exit(2)


@ready.command("provision")
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=10.0,
    show_default=True,
    help="Scan timeout in seconds",
)
@click.option(
    "--eid-type",
    type=click.Choice(["utc"], case_sensitive=False),
    default="utc",
    show_default=True,
    help="EID type (only 'utc' supported currently)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Show detailed progress messages",
)
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
    type=str,
    envvar="HUBBLE_API_TOKEN",
    default=None,
    show_default=False,
    help="API token (if not using HUBBLE_API_TOKEN env var)",
)
def ready_provision(
    timeout: float = 10.0,
    eid_type: str = "utc",
    verbose: bool = False,
    org_id: Optional[str] = None,
    token: Optional[str] = None,
) -> None:
    """
    Provision a Hubble Ready device.

    Scans for devices, lets you select one interactively, then provisions
    it by registering with the Hubble backend and writing the encryption
    key and configuration.

    The encryption mode (AES-256-CTR or AES-128-CTR) is automatically
    detected from the device during provisioning.

    Requires HUBBLE_ORG_ID and HUBBLE_API_TOKEN environment variables
    or --org-id and --token options.

    Example:
      hubblenetwork ready provision
      hubblenetwork ready provision -v
    """
    import questionary

    # Get credentials
    org_id_val, token_val = _get_org_and_token(org_id, token)

    try:
        org = Organization(org_id=org_id_val, api_token=token_val)
    except InvalidCredentialsError as e:
        raise click.ClickException(f"Invalid credentials: {e}")

    click.secho("Scanning for Hubble Ready devices...")
    devices = ready_mod.scan_ready_devices(timeout=timeout)

    if not devices:
        click.echo("\nNo Hubble Ready devices found.")
        return

    click.echo(f"\nFound {len(devices)} device(s):\n")

    # Interactive device selection
    selected = _select_ready_device(devices)
    if selected is None:
        click.echo("No device selected.")
        return

    # Log callback for verbose mode
    def log_step(msg: str) -> None:
        if verbose:
            click.secho(f"[STEP] {msg}")

    # Prompt for device name (use scanned name as default)
    default_name = selected.name or f"Device-{selected.address[-5:].replace(':', '')}"
    device_name = questionary.text(
        "Device name:",
        default=default_name,
    ).ask()

    if device_name is None:
        click.echo("Cancelled.")
        return

    click.echo("")

    # Perform provisioning
    click.echo(f"\nConnecting to {selected.address}...")
    try:
        result = ready_mod.provision_device(
            address=selected.address,
            org=org,
            device_name=device_name,
            scanned_device_name=selected.name,
            eid_type=eid_type.lower(),
            timeout=timeout,
            log_callback=log_step,
        )
    except Exception as e:
        click.secho(f"\n[ERROR] Provisioning failed: {e}", fg="red", err=True)
        sys.exit(2)

    if result.success:
        click.secho("\n[SUCCESS] Device provisioned!", fg="green")
        click.echo(f"  Device ID: {result.device_id}")
        click.echo(f"  Name: {result.device_name}")
        click.echo(f"  Encryption: {result.encryption_type}")
        click.echo(f"  Key: {result.device_key_base64}")
    else:
        click.secho(f"\n[ERROR] Provisioning failed: {result.error_message}", fg="red", err=True)
        sys.exit(2)


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
