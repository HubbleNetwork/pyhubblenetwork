# hubblenetwork/cli.py
from __future__ import annotations

import click
import os
import json
import sys
import time
import base64
from datetime import datetime
from typing import Optional
from hubblenetwork import Organization
from hubblenetwork import Device, DecryptedPacket, EncryptedPacket
from hubblenetwork import ble as ble_mod
from hubblenetwork import decrypt
from hubblenetwork import cloud
from hubblenetwork import InvalidCredentialsError


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


def _print_packet_table_header(show_loc=True, show_payload=True) -> None:
    click.secho("\nTIME                      ", nl=False, bold=True)
    click.secho("RSSI ", nl=False, bold=True)
    if show_loc:
        click.secho("COORDINATES           ", nl=False, bold=True)
    if show_payload:
        click.secho("PAYLOAD (B)", nl=False, bold=True)
    click.echo("")
    click.echo("--------------------------------------------------------------")


def _print_packet_table_row(pkt, show_loc=True, show_payload=True) -> None:
    ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")

    click.echo(f"{ts}  {pkt.rssi}  ", nl=False)
    if show_loc:
        loc = pkt.location
        click.echo(f"{loc.lat:.6f},{loc.lon:.6f}  ", nl=False)
    if show_payload:
        if isinstance(pkt, DecryptedPacket):
            click.secho(f'"{pkt.payload}"', nl=False)
        elif isinstance(pkt, EncryptedPacket):
            click.secho(f"{pkt.payload.hex()} ({len(pkt.payload)} bytes)", nl=False)
    click.echo("")


def _print_packets_tabular(pkts) -> None:
    _print_packet_table_header()
    for pkt in pkts:
        _print_packet_table_row(pkt)


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
    if len(pkts) == 0:
        click.echo("No packets!")
        return
    """Pretty-print an EncryptedPacket."""
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


def _print_packets(pkts, output: str = "pretty") -> None:
    if not output:
        _print_packets_tabular(pkts)
        return
    func_name = f"_print_packets_{output.lower().strip()}"
    func = getattr(sys.modules[__name__], func_name, None)
    if callable(func):
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
@click.option("--ingest", is_flag=True)
def ble_scan(
    timeout: Optional(int) = None, ingest: bool = False, key: str = None
) -> None:
    """
    Scan for UUID 0xFCA6 and print the first packet found within TIMEOUT seconds.

    Example:
      hubblenetwork ble scan 1
    """
    click.secho("[INFO] Scanning for Hubble devices...")
    _print_packet_table_header(show_payload=True if key else False, show_loc=False)

    if ingest:
        org = Organization(
            org_id=_get_env_or_fail("HUBBLE_ORG_ID"),
            api_token=_get_env_or_fail("HUBBLE_API_TOKEN"),
        )

    start = time.monotonic()
    deadline = None if timeout is None else start + timeout

    while deadline is None or time.monotonic() < deadline:
        this_timeout = None if deadline is None else max(deadline - time.monotonic(), 0)

        pkt = ble_mod.scan_single(timeout=this_timeout)
        if not pkt:
            break

        # If we have a key, attempt to decrypt
        if key:
            decoded_key = bytearray(base64.b64decode(key))
            decrypted_pkt = decrypt(decoded_key, pkt)
            if decrypted_pkt:
                _print_packet_table_row(
                    decrypted_pkt, show_payload=True, show_loc=False
                )
                # We only allow ingestion of packets you know the key of
                # so we don't ingest bogus data in the backend
                if ingest:
                    org.ingest_packet(pkt)
        else:
            _print_packet_table_row(pkt, show_payload=False, show_loc=False)


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
    show_default=False,  # show default in --help
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
