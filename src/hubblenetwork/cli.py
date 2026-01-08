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


class _StreamingTablePrinter:
    """Helper class to print table rows as they arrive, printing header once."""

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


def _print_packet_pretty(pkt) -> None:
    ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
    loc = pkt.location
    loc_str = (
        f"{loc.lat:.6f},{loc.lon:.6f}"
        if getattr(loc, "lat", None) is not None
        else "unknown"
    )
    click.echo(click.style("=== BLE packet ===", bold=True))
    click.echo(f"time:    {ts}")
    click.echo(f"rssi:    {pkt.rssi} dBm")
    click.echo(f"loc:     {loc_str}")
    # Show both hex and length
    if isinstance(pkt, DecryptedPacket):
        click.echo(f'payload: "{pkt.payload}"')
    elif isinstance(pkt, EncryptedPacket):
        click.echo(f"payload: {pkt.payload.hex()} ({len(pkt.payload)} bytes)")


def _print_packets_pretty(pkts) -> None:
    """Pretty-print a list of packets."""
    if len(pkts) == 0:
        click.echo("No packets!")
        return
    for pkt in pkts:
        _print_packet_pretty(pkt)


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


def _print_packets_kepler(pkts) -> None:
    """
    https://kepler.gl/demo

    Can ingest this JSON to visualize a travel path for a device.
    """
    data = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "properties": {"vendor": "A"},
                "geometry": {"type": "LineString", "coordinates": []},
            }
        ],
    }

    for pkt in pkts:
        row = [pkt.location.lon, pkt.location.lat, 0, pkt.timestamp]
        data["features"][0]["geometry"]["coordinates"].append(row)
    click.echo(json.dumps(data))


_OUTPUT_FORMATS = {
    "pretty": "_print_packets_pretty",
    "csv": "_print_packets_csv",
    "kepler": "_print_packets_kepler",
    "tabular": "_print_packets_tabular",
}


def _print_packets(pkts, output: str = "pretty") -> None:
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


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
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
    show_default=False,
    help="Timeout when scanning",
)
@click.option(
    "--key",
    "-k",
    required=True,
    type=str,
    default=None,
    show_default=False,
    help="Attempt to decrypt any received packet with the given key",
)
@click.option(
    "--debug",
    "-d",
    is_flag=True,
    default=False,
    help="Enable debug logging to stderr",
)
def ble_detect(
    timeout: Optional[int] = None, key: str = None, debug: bool = False
) -> None:
    """
    Scan for a single BLE packet and decrypt with key. Returns JSON output.

    This mode is designed for programmatic validation of BLE packets.
    The key parameter is required. JSON goes to stdout, errors/logs go to stderr.
    Check the 'success' field (boolean) in JSON.

    Example:
      hubblenetwork ble detect --key "yourBase64Key=" --timeout 20 --debug
    """
    # Set log level based on debug flag
    logger.setLevel(logging.DEBUG if debug else logging.WARNING)

    # Try to decode the base64 key
    try:
        decoded_key = bytearray(base64.b64decode(key))
        logger.debug("Key decoded successfully")
    except (binascii.Error, Exception) as e:
        logger.error(f"Base64 decoding failed: {e}")
        result = {"success": False, "error": "Base64 decoding failed for provided key"}
        click.echo(json.dumps(result))
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
            result = {"success": False, "error": f"BLE scanning error: {str(e)}"}
            click.echo(json.dumps(result))
            return

        # Check if packet was found
        if not pkt:
            # Timeout reached without finding any packet
            logger.error("Timeout: No BLE packets found")
            result = {
                "success": False,
                "error": "No BLE packets found within timeout period",
            }
            click.echo(json.dumps(result))
            return

        logger.debug("Packet received, attempting decryption...")

        # Attempt to decrypt the packet
        decrypted_pkt = decrypt(decoded_key, pkt)

        if decrypted_pkt:
            # If we can decrypt it, build success JSON
            datetime_str = datetime.fromtimestamp(decrypted_pkt.timestamp).strftime(
                "%c"
            )
            logger.info("Packet decrypted successfully!")
            result = {
                "success": True,
                "packet": {
                    "datetime": datetime_str,
                    "rssi": decrypted_pkt.rssi,
                    "payload_bytes": len(decrypted_pkt.payload),
                },
            }
            click.echo(json.dumps(result))
            return

        logger.debug(
            "Decryption failed (doesn't match key), scanning for another packet..."
        )

    # If we exit the loop, it means we've exceeded the timeout without finding a valid packet
    result = {"success": False, "error": "No valid packets found within timeout period"}
    click.echo(json.dumps(result))
    return


@ble.command("scan")
@click.option(
    "--timeout",
    "-t",
    type=int,
    show_default=False,
    help="Timeout when scanning",
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
@click.option("--ingest", is_flag=True)
def ble_scan(
    timeout: Optional[int] = None,
    ingest: bool = False,
    key: Optional[str] = None,
    days: int = 2,
) -> None:
    """
    Scan for UUID 0xFCA6 and print the first packet found within TIMEOUT seconds.

    Example:
      hubblenetwork ble scan 1
    """
    click.secho("[INFO] Scanning for Hubble devices...")
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
            raise click.ClickException(f"Invalid base64 key: {e}")

    # Use streaming table printer to display packets as they arrive
    table_printer = _StreamingTablePrinter()

    while deadline is None or time.monotonic() < deadline:
        this_timeout = None if deadline is None else max(deadline - time.monotonic(), 0)

        pkt = ble_mod.scan_single(timeout=this_timeout)
        if not pkt:
            break

        # If we have a key, attempt to decrypt
        if decoded_key:
            decrypted_pkt = decrypt(decoded_key, pkt, days=days)
            if decrypted_pkt:
                table_printer.print_row(decrypted_pkt)
                # We only allow ingestion of packets you know the key of
                # so we don't ingest bogus data in the backend
                if ingest:
                    org.ingest_packet(pkt)
        else:
            table_printer.print_row(pkt)


@ble.command("check-time")
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=None,
    show_default=False,
    help="Timeout when scanning (default: no timeout)",
)
@click.option(
    "--key",
    "-k",
    required=True,
    type=str,
    help="Key to use for checking time counter resolution (base64 encoded)",
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
    "-f",
    type=str,
    default=None,
    show_default=False,  # show default in --help
    help="Output format (None, pretty, csv)",
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
    org: Organization, device_id, format: str = None, days: int = 7
) -> None:
    device = Device(id=device_id)
    packets = org.retrieve_packets(device, days=days)
    _print_packets(packets, format)


def main(argv: Optional[list[str]] = None) -> int:
    """
    Entry point used by console_scripts.

    Returns a process exit code instead of letting Click call sys.exit for easier testing.
    """
    try:
        # standalone_mode=False prevents Click from calling sys.exit itself.
        cli.main(args=argv, prog_name="hubble", standalone_mode=False)
    except SystemExit as e:
        return int(e.code)
    except Exception as e:  # safety net to avoid tracebacks in user CLI
        click.secho(f"Unexpected error: {e}", fg="red", err=True)
        return 2
    return 0


if __name__ == "__main__":
    # Forward command-line args (excluding the program name) to main()
    raise SystemExit(main())
