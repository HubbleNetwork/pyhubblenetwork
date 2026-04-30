# hubblenetwork/cli.py
from __future__ import annotations

import click
import os
import json
import signal
import sys
import time
import base64
import binascii
import logging
import uuid
from datetime import datetime
from functools import partial
from typing import Optional, List
from tabulate import tabulate
from hubblenetwork import Organization
from hubblenetwork import Device, DecryptedPacket, EncryptedPacket, decrypt_eax
from hubblenetwork.packets import SatellitePacket, UnencryptedPacket, AesEaxPacket, UnknownPacket
from hubblenetwork import ble as ble_mod
from hubblenetwork import ready as ready_mod
from hubblenetwork import sat as sat_mod
from hubblenetwork import decrypt, UNIX_TIME, DEVICE_UPTIME
from hubblenetwork.crypto import find_time_counter_delta
from hubblenetwork import cloud
from hubblenetwork import InvalidCredentialsError
from hubblenetwork.errors import BackendError

# Set up logger for CLI (outputs to stderr)
logger = logging.getLogger(__name__)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
logger.addHandler(_handler)


def _parse_key(key_str: str) -> bytes:
    """Parse an encryption key from hex or base64. Returns raw bytes.

    Accepts 128-bit (16 bytes) or 256-bit (32 bytes) keys.
    Strings of exactly 32 or 64 characters are tried as hex first, then base64.
    """
    s = key_str.strip()
    if len(s) in (32, 64):
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    try:
        key_bytes = base64.b64decode(s, validate=True)
    except binascii.Error as e:
        raise ValueError(
            f"Invalid key format: {e}. Provide hex (32 or 64 hex chars) or base64."
        )
    if len(key_bytes) not in (16, 32):
        raise ValueError(
            f"Key must be 16 bytes (AES-128) or 32 bytes (AES-256), got {len(key_bytes)}."
        )
    return key_bytes


def _validate_info(msg):
    click.secho("[INFO] ", fg="cyan", bold=True, nl=False)
    click.echo(msg + "... ", nl=False)


def _validate_success():
    click.secho("[SUCCESS]", fg="green", bold=True)


def _validate_error(msg):
    click.secho("[ERROR]", fg="red", bold=True)
    click.secho(f"\n{msg}", bold=True)
    sys.exit(1)


def _get_pkt_from_be_with_timestamp(org, device, timestamp):
    backend_pkts = org.retrieve_packets(device, days=1)
    for p in backend_pkts:
        if p.timestamp == timestamp:
            return p
    return None


def _detect_eid_type(
    key: bytes,
    pkts: List[EncryptedPacket],
) -> tuple[Optional[EncryptedPacket], Optional[DecryptedPacket], Optional[str], bool]:
    epoch_pkt = None
    epoch_dec = None
    counter_pkt = None
    counter_dec = None
    for pkt in pkts:
        if epoch_pkt is None:
            result = decrypt(key, pkt)
            if result:
                epoch_pkt = pkt
                epoch_dec = result
        if counter_pkt is None:
            result = decrypt(key, pkt, counter_mode=DEVICE_UPTIME)
            if result:
                counter_pkt = pkt
                counter_dec = result
        if epoch_pkt and counter_pkt:
            break
    if epoch_pkt and counter_pkt:
        return (epoch_pkt, epoch_dec, "AMBIGUOUS", True)
    if epoch_pkt:
        return (epoch_pkt, epoch_dec, UNIX_TIME, False)
    if counter_pkt:
        return (counter_pkt, counter_dec, DEVICE_UPTIME, False)
    return (None, None, None, False)


def _announce_auto_detect(auto_ctr: bool, auto_eax: bool, *, suppress: bool) -> None:
    if suppress or not (auto_ctr or auto_eax):
        return
    parts = []
    if auto_ctr:
        parts.append("AES-CTR counter_source")
    if auto_eax:
        parts.append("AES-EAX period_exponent (0..15)")
    click.secho(
        f"[WARN] No {' / '.join(parts)} provided. Auto-detecting "
        f"decryption configuration from incoming packets...",
        fg="yellow",
        err=True,
    )


def _decrypt_eax_with_detect(
    key: bytes,
    pkt: AesEaxPacket,
    *,
    auto_detect: bool,
    fixed_exponent: int,
    cache: dict,
    announced: list[str],
    suppress_info: bool,
) -> Optional[DecryptedPacket]:
    if not auto_detect:
        return decrypt_eax(key, pkt, period_exponent=fixed_exponent)

    cached = cache.get(pkt.eid)
    if cached is not None:
        result = decrypt_eax(key, pkt, period_exponent=cached)
        if result:
            return result

    for candidate in range(16):
        result = decrypt_eax(key, pkt, period_exponent=candidate)
        if result is None:
            continue
        cache[pkt.eid] = candidate
        if not announced and not suppress_info:
            announced.append("eax")
            click.secho(
                f"[INFO] Detected: AES-128-EAX, counter_source=DEVICE_UPTIME, "
                f"period_exponent={candidate} (period={1 << candidate}s)",
                fg="green",
                err=True,
            )
        return result
    return None


def _decrypt_ctr_with_detect(
    key: bytes,
    pkt: EncryptedPacket,
    *,
    auto_detect: bool,
    fixed_counter_mode: str,
    days: int,
    cache: dict,
    announced: list[str],
    suppress_info: bool,
) -> Optional[DecryptedPacket]:
    if not auto_detect:
        return decrypt(key, pkt, days=days, counter_mode=fixed_counter_mode)

    def _try(mode: str) -> Optional[DecryptedPacket]:
        kwargs = {"counter_mode": mode}
        if mode == UNIX_TIME:
            kwargs["days"] = days
        return decrypt(key, pkt, **kwargs)

    if pkt.eid is not None:
        cached = cache.get(pkt.eid)
        if cached is not None:
            result = _try(cached)
            if result:
                return result

    for mode in (UNIX_TIME, DEVICE_UPTIME):
        result = _try(mode)
        if result is None:
            continue
        if pkt.eid is not None:
            cache[pkt.eid] = mode
        if not announced and not suppress_info:
            announced.append("ctr")
            variant = "AES-128-CTR" if len(key) == 16 else "AES-256-CTR"
            click.secho(
                f"[INFO] Detected: {variant}, counter_source={mode}",
                fg="green",
                err=True,
            )
        return result
    return None


def _format_payload(payload, fmt: str) -> str:
    """Format packet payload bytes for display."""
    if not isinstance(payload, bytes):
        return str(payload)
    if fmt == "hex":
        return payload.hex().upper()
    elif fmt == "string":
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            click.echo("Warning: payload contains non-UTF-8 bytes", err=True)
            return "<invalid UTF-8>"
    else:  # base64 (default)
        return base64.b64encode(payload).decode("ascii")


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


def _add_raw_adv_fields(data: dict, pkt) -> None:
    """Emit protocol_version/eid/auth_tag to `data` when present on `pkt`."""
    version = getattr(pkt, "protocol_version", None)
    if version is not None:
        data["protocol_version"] = version
    eid = getattr(pkt, "eid", None)
    if eid is not None:
        data["eid"] = f"{eid:x}"
    auth_tag = getattr(pkt, "auth_tag", None)
    if auth_tag is not None:
        data["auth_tag"] = auth_tag.hex()


def _ctr_display_payload(pkt) -> bytes:
    """Return payload bytes with the AES-CTR header stripped, if applicable.

    The seq_no/EID/auth_tag header is already rendered in dedicated columns,
    so only the trailing ciphertext belongs in the PAYLOAD field.
    """
    if isinstance(pkt, EncryptedPacket) and len(pkt.payload) >= 10:
        return pkt.payload[10:]
    return pkt.payload


def _packet_to_dict(
    pkt,
    payload_format: str = "base64",
    decrypt_status: Optional[str] = None,
) -> dict:
    """Convert a packet to a dictionary for JSON serialization."""
    ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
    data = {
        "timestamp": pkt.timestamp,
        "datetime": ts,
        "rssi": pkt.rssi,
    }

    _add_raw_adv_fields(data, pkt)

    if isinstance(pkt, UnencryptedPacket):
        data["network_id"] = pkt.network_id
    elif isinstance(pkt, AesEaxPacket):
        data["nonce_salt"] = pkt.nonce_salt.hex()
    elif isinstance(pkt, DecryptedPacket):
        data["counter"] = pkt.counter
        data["sequence"] = pkt.sequence

    data["payload"] = _format_payload(_ctr_display_payload(pkt), payload_format)

    if not pkt.location.fake:
        data["location"] = {
            "lat": pkt.location.lat,
            "lon": pkt.location.lon,
        }

    if decrypt_status is not None:
        data["decrypt_status"] = decrypt_status

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

    def __init__(self, show_decrypt_status: bool = False):
        self._packet_count = 0
        self._show_decrypt_status = show_decrypt_status

    def print_row(self, pkt, decrypt_status: Optional[str] = None) -> None:
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
        "TIME": 10,
        "RSSI": 6,
        "COUNTER": 8,
        "NET_ID": 12,
        "VERSION": 8,
        "EID": 20,
        "TAG": 10,
        "SALT/SEQ": 10,
        "COORDINATES": 22,
        "PAYLOAD": 20,
        "DECRYPT": 8,
    }

    def __init__(self, payload_format: str = "base64", show_decrypt_status: bool = False):
        super().__init__(show_decrypt_status=show_decrypt_status)
        self._header_printed = False
        self._headers: List[str] = []
        self._show_net_id = False
        self._show_coordinates = False
        self._payload_format = payload_format

    def _determine_columns(self, pkt) -> List[str]:
        """Determine column headers based on the first packet seen.

        AES-EAX and AES-CTR packets share a single unified layout — VERSION,
        EID, TAG, COUNTER, and SALT/SEQ are always present, with "-" shown
        where a field doesn't apply.
        """
        self._show_net_id = isinstance(pkt, UnencryptedPacket)
        self._show_coordinates = not pkt.location.fake

        headers: List[str] = []
        if self._show_decrypt_status:
            headers.append("DECRYPT")
        headers.extend(
            ["TIMESTAMP", "TIME", "RSSI", "VERSION", "EID", "TAG", "COUNTER", "SALT/SEQ"]
        )
        if self._show_net_id:
            headers.append("NET_ID")
        if self._show_coordinates:
            headers.append("COORDINATES")
        headers.append("PAYLOAD")

        return headers

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

    def print_row(self, pkt, decrypt_status: Optional[str] = None) -> None:
        """Print a single packet row, printing header first if needed."""
        if not self._header_printed:
            self._headers = self._determine_columns(pkt)
            click.echo("")
            click.echo(self._make_separator())
            click.secho(self._format_row(self._headers), bold=True)
            click.echo(self._make_separator())
            self._header_printed = True

        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S")
        row: List = []
        if self._show_decrypt_status:
            row.append("OK" if decrypt_status == "ok" else "FAIL" if decrypt_status == "fail" else "-")
        row.extend([pkt.timestamp, ts, pkt.rssi if pkt.rssi is not None else "None"])

        version = getattr(pkt, "protocol_version", None)
        row.append(version if version is not None else "-")

        eid = getattr(pkt, "eid", None)
        row.append(f"{eid:x}" if eid is not None else "-")

        auth_tag = getattr(pkt, "auth_tag", None)
        row.append(auth_tag.hex() if auth_tag is not None else "-")

        if isinstance(pkt, DecryptedPacket) and pkt.counter is not None:
            row.append(pkt.counter)
        else:
            row.append("-")

        if isinstance(pkt, DecryptedPacket):
            row.append(pkt.sequence if pkt.sequence is not None else "-")
        elif isinstance(pkt, AesEaxPacket):
            row.append(int.from_bytes(pkt.nonce_salt, "big"))
        else:
            row.append("-")

        if self._show_net_id:
            row.append(pkt.network_id if isinstance(pkt, UnencryptedPacket) else "-")

        if self._show_coordinates:
            loc = pkt.location
            row.append(f"{loc.lat:.6f},{loc.lon:.6f}")

        row.append(_format_payload(_ctr_display_payload(pkt), self._payload_format))

        click.echo(self._format_row(row))
        click.echo(self._make_separator())
        self._packet_count += 1


class _StreamingJsonPrinter(_StreamingPrinterBase):
    """Print packets as a streaming JSON array."""

    def __init__(
        self,
        payload_format: str = "base64",
        to_dict_fn=None,
        show_decrypt_status: bool = False,
    ):
        super().__init__(show_decrypt_status=show_decrypt_status)
        self._array_started = False
        self._payload_format = payload_format
        self._to_dict_fn = to_dict_fn or _packet_to_dict

    @property
    def suppress_info_messages(self) -> bool:
        return True

    def print_row(self, pkt, decrypt_status: Optional[str] = None) -> None:
        """Print a single packet as JSON."""
        status = decrypt_status if self._show_decrypt_status else None
        pkt_dict = self._to_dict_fn(pkt, self._payload_format, decrypt_status=status)
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


# ---------------------------------------------------------------------------
# Satellite streaming printers
# ---------------------------------------------------------------------------


def _sat_packet_to_dict(
    pkt: SatellitePacket,
    payload_format: str = "base64",
    **_: object,
) -> dict:
    """Convert a SatellitePacket to a dictionary for JSON serialization."""
    ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
    return {
        "device_id": pkt.device_id,
        "seq_num": pkt.seq_num,
        "device_type": pkt.device_type,
        "timestamp": pkt.timestamp,
        "datetime": ts,
        "rssi_dB": pkt.rssi_dB,
        "channel_num": pkt.channel_num,
        "freq_offset_hz": pkt.freq_offset_hz,
        "payload": _format_payload(pkt.payload, payload_format),
    }


class _SatStreamingTablePrinter(_StreamingPrinterBase):
    """Print satellite packet rows as they arrive."""

    _COL_WIDTHS = {
        "DEVICE_ID": 12,
        "SEQ": 6,
        "TYPE": 8,
        "TIME": 26,
        "RSSI_DB": 8,
        "CHANNEL": 8,
        "FREQ_OFFSET": 12,
        "PAYLOAD": 20,
    }

    _HEADERS = ["DEVICE_ID", "SEQ", "TYPE", "TIME", "RSSI_DB", "CHANNEL", "FREQ_OFFSET", "PAYLOAD"]

    def __init__(self, payload_format: str = "base64"):
        super().__init__()
        self._header_printed = False
        self._payload_format = payload_format

    def _format_row(self, values: List) -> str:
        parts = []
        for i, val in enumerate(values):
            width = self._COL_WIDTHS.get(self._HEADERS[i], 10)
            parts.append(f"{str(val):<{width}}")
        return "| " + " | ".join(parts) + " |"

    def _make_separator(self) -> str:
        parts = []
        for header in self._HEADERS:
            width = self._COL_WIDTHS.get(header, 10)
            parts.append("-" * width)
        return "+-" + "-+-".join(parts) + "-+"

    def print_row(self, pkt: SatellitePacket) -> None:
        if not self._header_printed:
            click.echo("")
            click.echo(self._make_separator())
            click.secho(self._format_row(self._HEADERS), bold=True)
            click.echo(self._make_separator())
            self._header_printed = True

        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
        row = [
            pkt.device_id,
            pkt.seq_num,
            pkt.device_type,
            ts,
            f"{pkt.rssi_dB:.1f}",
            pkt.channel_num,
            f"{pkt.freq_offset_hz:.1f}",
            _format_payload(pkt.payload, self._payload_format),
        ]
        click.echo(self._format_row(row))
        click.echo(self._make_separator())
        self._packet_count += 1


_SAT_STREAMING_PRINTERS = {
    "tabular": _SatStreamingTablePrinter,
    "json": partial(_StreamingJsonPrinter, to_dict_fn=_sat_packet_to_dict),
}


def _print_packets_tabular(pkts: List, payload_format: str = "base64") -> None:
    """Print packets in a formatted table using tabulate."""
    if not pkts:
        click.echo("No packets!")
        return

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
            row.append(_format_payload(pkt.payload, payload_format))

        rows.append(row)

    click.echo("\n" + tabulate(rows, headers=headers, tablefmt="grid"))


def _print_packets_csv(pkts, payload_format: str = "base64") -> None:
    click.echo("timestamp, datetime, latitude, longitude, payload")
    for pkt in pkts:
        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
        payload_str = _format_payload(pkt.payload, payload_format)
        click.echo(
            f'{pkt.timestamp}, {ts}, {pkt.location.lat:.6f}, {pkt.location.lon:.6f}, "{payload_str}"'
        )


def _print_packets_json(pkts, payload_format: str = "base64") -> None:
    """Print packets as a JSON array."""
    json_packets = [_packet_to_dict(pkt, payload_format) for pkt in pkts]
    click.echo(json.dumps(json_packets, indent=2))


def _print_packets(pkts, output: str = "tabular", payload_format: str = "base64") -> None:
    format_key = (output or "tabular").lower().strip()
    if format_key == "json":
        _print_packets_json(pkts, payload_format)
    elif format_key == "csv":
        _print_packets_csv(pkts, payload_format)
    else:
        _print_packets_tabular(pkts, payload_format)


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
    help="Key to decrypt packets (hex or base64, 16 or 32 bytes)",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=2,
    show_default=True,
    help="Number of days to check back when decrypting",
)
@click.option(
    "--counter-mode",
    type=click.Choice(["UNIX_TIME", "DEVICE_UPTIME"], case_sensitive=False),
    default="UNIX_TIME",
    show_default=True,
    help="EID counter mode for AES-CTR packets",
)
@click.option(
    "--period-exponent",
    "-e",
    type=int,
    default=0,
    show_default=True,
    help="EID rotation period exponent for AES-EAX packets (0-15). Period = 2^n seconds.",
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
    "--payload-format",
    "payload_format",
    type=click.Choice(["base64", "hex", "string"], case_sensitive=False),
    default="base64",
    show_default=True,
    help="Encoding format for packet payload",
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Enable debug logging to stderr",
)
@click.pass_context
def ble_detect(
    ctx,
    timeout: Optional[int] = None,
    key: str = None,
    days: int = 2,
    counter_mode: str = "UNIX_TIME",
    period_exponent: int = 0,
    output_format: str = "tabular",
    payload_format: str = "base64",
    debug: bool = False,
) -> None:
    """
    Scan for a single BLE packet and decrypt with key.

    This mode is designed for programmatic validation of BLE packets.
    The key parameter is required. Check the 'success' field in JSON output.

    Example:
      hubblenetwork ble detect --key "a562a2f7e4c62bed52ab09633878f62b" --timeout 20
      hubblenetwork ble detect -k "q9vH3u2J4aN8Rw1KpZsO+A==" -o tabular
    """
    use_json = output_format.lower() == "json"

    if counter_mode == DEVICE_UPTIME:
        days_source = ctx.get_parameter_source("days")
        if days_source == click.core.ParameterSource.COMMANDLINE:
            raise click.UsageError(
                "--counter-mode DEVICE_UPTIME and --days are mutually exclusive"
            )

    # Set log level based on debug flag
    logger.setLevel(logging.DEBUG if debug else logging.WARNING)

    def _output_error(msg: str) -> None:
        if use_json:
            click.echo(json.dumps({"success": False, "error": msg}))
        else:
            click.secho(f"[ERROR] {msg}", fg="red", err=True)

    try:
        decoded_key = bytearray(_parse_key(key))
        logger.debug("Key decoded successfully")
    except ValueError as e:
        logger.error(f"Key decoding failed: {e}")
        _output_error(f"Key decoding failed: {e}")
        return

    def _explicit(name: str) -> bool:
        return ctx.get_parameter_source(name) == click.core.ParameterSource.COMMANDLINE

    auto_detect_ctr = not _explicit("counter_mode")
    auto_detect_eax = not _explicit("period_exponent")

    _announce_auto_detect(auto_detect_ctr, auto_detect_eax, suppress=use_json)

    detected_ctr_modes: dict = {}
    detected_eax_exponents: dict = {}
    announced: list[str] = []

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

        decrypted_pkt = None
        if isinstance(pkt, AesEaxPacket):
            decrypted_pkt = _decrypt_eax_with_detect(
                decoded_key,
                pkt,
                auto_detect=auto_detect_eax,
                fixed_exponent=period_exponent,
                cache=detected_eax_exponents,
                announced=announced,
                suppress_info=use_json,
            )
        elif isinstance(pkt, EncryptedPacket):
            decrypted_pkt = _decrypt_ctr_with_detect(
                decoded_key,
                pkt,
                auto_detect=auto_detect_ctr,
                fixed_counter_mode=counter_mode,
                days=days,
                cache=detected_ctr_modes,
                announced=announced,
                suppress_info=use_json,
            )
        # UnencryptedPacket and UnknownPacket fall through — keep scanning.

        if decrypted_pkt:
            # If we can decrypt it, output success
            datetime_str = datetime.fromtimestamp(decrypted_pkt.timestamp).strftime(
                "%c"
            )
            logger.info("Packet decrypted successfully!")

            payload_str = _format_payload(decrypted_pkt.payload, payload_format)
            if use_json:
                result = {
                    "success": True,
                    "packet": {
                        "datetime": datetime_str,
                        "rssi": decrypted_pkt.rssi,
                        "payload": payload_str,
                        "counter": decrypted_pkt.counter,
                    },
                }
                click.echo(json.dumps(result))
            else:
                click.secho("[SUCCESS] ", fg="green", nl=False)
                click.echo(
                    f"Packet decrypted: {datetime_str}, RSSI: {decrypted_pkt.rssi} dBm, payload: {payload_str}, counter: {decrypted_pkt.counter}"
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
    help="Key to decrypt packets (hex or base64, 16 or 32 bytes)",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=2,
    show_default=True,
    help="Days to search when decrypting AES-CTR packets with UNIX_TIME counter mode",
)
@click.option(
    "--counter-mode",
    type=click.Choice([UNIX_TIME, DEVICE_UPTIME], case_sensitive=False),
    default=UNIX_TIME,
    show_default=True,
    help="EID counter mode for AES-CTR packets",
)
@click.option(
    "--period-exponent",
    "-e",
    type=int,
    default=0,
    show_default=True,
    help="EID rotation period exponent for AES-EAX packets (0-15). Period = 2^n seconds. Matches rot_exp in device config.",
)
@click.option(
    "--network-id",
    type=int,
    default=None,
    show_default=False,
    help="Filter by network ID (unencrypted protocol only)",
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
@click.option(
    "--payload-format",
    "payload_format",
    type=click.Choice(["base64", "hex", "string"], case_sensitive=False),
    default="base64",
    show_default=True,
    help="Encoding format for packet payload",
)
@click.option(
    "--show-failed-decryption",
    is_flag=True,
    default=False,
    help="Show encrypted packets that fail decryption/authentication with the provided key. Adds a DECRYPT column indicating OK/FAIL.",
)
@click.pass_context
def ble_scan(
    ctx,
    timeout: Optional[int] = None,
    count: Optional[int] = None,
    network_id: Optional[int] = None,
    ingest: bool = False,
    key: Optional[str] = None,
    days: int = 2,
    counter_mode: str = "UNIX_TIME",
    period_exponent: int = 0,
    output_format: str = "tabular",
    payload_format: str = "base64",
    show_failed_decryption: bool = False,
) -> None:
    """
    Scan for UUID 0xFCA6 and print packets as they are found.

    Automatically detects encrypted vs unencrypted protocol packets.

    Example:
      hubblenetwork ble scan --timeout 30
      hubblenetwork ble scan --key "a562a2f7e4c62bed52ab09633878f62b" --timeout 60
      hubblenetwork ble scan -o json --timeout 10
      hubblenetwork ble scan -n 5              # Stop after 5 packets
      hubblenetwork ble scan --network-id 4378792717
    """
    if counter_mode == DEVICE_UPTIME:
        if not key:
            raise click.UsageError("--counter-mode DEVICE_UPTIME requires --key")
        days_source = ctx.get_parameter_source("days")
        if days_source == click.core.ParameterSource.COMMANDLINE:
            raise click.UsageError(
                "--counter-mode DEVICE_UPTIME and --days are mutually exclusive"
            )

    # Get the appropriate streaming printer
    printer_class = _STREAMING_PRINTERS.get(
        output_format.lower(), _StreamingTablePrinter
    )
    printer = printer_class(
        payload_format=payload_format,
        show_decrypt_status=show_failed_decryption,
    )

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
            decoded_key = bytearray(_parse_key(key))
        except ValueError as e:
            if printer.suppress_info_messages:
                click.echo(json.dumps({"error": f"Invalid base64 key: {e}"}))
                return
            raise click.ClickException(f"Invalid base64 key: {e}")

    # Click's parameter source lets users disable auto-detect by passing the
    # default value verbatim — otherwise we couldn't tell "default" apart
    # from "user explicitly chose UNIX_TIME / exponent=0".
    def _explicit(name: str) -> bool:
        return ctx.get_parameter_source(name) == click.core.ParameterSource.COMMANDLINE

    auto_detect_ctr = decoded_key is not None and not _explicit("counter_mode")
    auto_detect_eax = decoded_key is not None and not _explicit("period_exponent")

    _announce_auto_detect(
        auto_detect_ctr, auto_detect_eax, suppress=printer.suppress_info_messages
    )

    detected_ctr_modes: dict = {}
    detected_eax_exponents: dict = {}
    announced: list[str] = []

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

            # Unencrypted packets: apply network_id filter, print directly
            if isinstance(pkt, UnencryptedPacket):
                if network_id is not None and pkt.network_id != network_id:
                    continue
                printer.print_row(pkt)
            # AES-EAX packets: decrypt if key provided, else show raw fields
            elif isinstance(pkt, AesEaxPacket):
                if decoded_key:
                    decrypted_pkt = _decrypt_eax_with_detect(
                        decoded_key,
                        pkt,
                        auto_detect=auto_detect_eax,
                        fixed_exponent=period_exponent,
                        cache=detected_eax_exponents,
                        announced=announced,
                        suppress_info=printer.suppress_info_messages,
                    )
                    if decrypted_pkt:
                        printer.print_row(decrypted_pkt, decrypt_status="ok")
                    elif show_failed_decryption:
                        printer.print_row(pkt, decrypt_status="fail")
                else:
                    printer.print_row(pkt)
            elif isinstance(pkt, EncryptedPacket):
                if decoded_key:
                    decrypted_pkt = _decrypt_ctr_with_detect(
                        decoded_key,
                        pkt,
                        auto_detect=auto_detect_ctr,
                        fixed_counter_mode=counter_mode,
                        days=days,
                        cache=detected_ctr_modes,
                        announced=announced,
                        suppress_info=printer.suppress_info_messages,
                    )
                    if decrypted_pkt:
                        printer.print_row(decrypted_pkt, decrypt_status="ok")
                        if ingest:
                            org.ingest_packet(pkt)
                    elif show_failed_decryption:
                        printer.print_row(pkt, decrypt_status="fail")
                else:
                    printer.print_row(pkt)
            elif isinstance(pkt, UnknownPacket):
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
    help="Key for checking time counter (hex or base64, 16 or 32 bytes)",
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
      hubblenetwork ble check-time --key "a562a2f7e4c62bed52ab09633878f62b" --timeout 30
    """
    try:
        decoded_key = bytearray(_parse_key(key))
    except ValueError as e:
        if json_output:
            click.echo(json.dumps({"error": str(e)}))
        else:
            click.secho(f"[ERROR] {e}", fg="red", err=True)
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


@ble.command("validate")
@click.option(
    "--key",
    "-k",
    type=str,
    required=True,
    show_default=False,
    help="Device key (to test packet encryption)",
)
@click.option(
    "--device-id",
    "-d",
    type=str,
    required=True,
    show_default=False,
    help="Device ID (to test backend)",
)
@click.option(
    "--org-id",
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
    help="Token (if not using HUBBLE_API_TOKEN env var)",
)
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=30,
    show_default=True,
    help="BLE scan timeout in seconds",
)
def ble_validate(key: str, device_id: str, org_id: str, token: str, timeout: int) -> None:
    """
    Validate the operation of a Hubble device, including:

    \b
    - Valid credentials passed in
    - Device registration (must be a registered device)
    - BLE advertisements
    - Advertisement encryption
    - Backend ingestion/retrieval of data

    NOTE: HUBBLE_ORG_ID and HUBBLE_API_TOKEN env vars must be set
    unless --org-id and --token are provided.
    """

    # Step 1: Validate inputs
    _validate_info("Validating format of inputs")
    try:
        decoded_key = _parse_key(key)
    except ValueError as e:
        _validate_error(
            f'Incorrectly formatted device key: {e}'
            '\nAccepted formats (fake keys):'
            '\n Hex 16-byte: "a562a2f7e4c62bed52ab09633878f62b"'
            '\n Hex 32-byte: "a562a2f7e4c62bed52ab09633878f62ba562a2f7e4c62bed52ab09633878f62b"'
            '\n Base64 16-byte: "q9vH3u2J4aN8Rw1KpZsO+A=="'
            '\n Base64 32-byte: "N4e7xq9X1pQ0sVbY2mT3uA6fH9rK2dW5cG8jL1oQ0vU="'
        )
    try:
        uuid.UUID(device_id)
    except ValueError:
        _validate_error(
            'Device UUID formatted incorrectly.'
            '\nMust be in standard 8-4-4-4-12 format (removing hyphens accepted).'
            '\nExample UUID: "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"'
            '\n\nIf you are having troubles with your UUID please contact support@hubble.com'
        )
    _validate_success()

    # Step 2: Get credentials
    _validate_info("Getting organization ID and API token")
    try:
        org_id, token = _get_org_and_token(org_id, token)
    except click.ClickException:
        _validate_error("HUBBLE_ORG_ID and/or HUBBLE_API_TOKEN environment variables not set")
    _validate_success()

    # Step 3: Validate org credentials
    _validate_info("Validating organization credentials")
    try:
        org = Organization(
            org_id=org_id,
            api_token=token,
        )
    except InvalidCredentialsError:
        _validate_error("Invalid credentials (Org ID or API token) passed in.")
    _validate_success()

    # Step 4: Validate device registration
    _validate_info("Validating that the given device is registered")
    device = Device(id=device_id)
    if not any(d.id == device_id for d in org.list_devices()):
        _validate_error("Device ID not found in backend")
    _validate_success()

    # Step 5: BLE scan
    _validate_info(f"Scanning for Hubble-compatible advertisers (timeout={timeout}s)")
    pkts = ble_mod.scan(timeout=timeout)
    if not pkts:
        _validate_error(
            'No Hubble advertisements found.'
            '\n\nNOTE: This may be due to a slow advertising interval and BLE-scanning'
            '\n      optimizations done by your operating system. Try running this'
            '\n      script again if your advertising interval is slow.'
            '\n\nOther debug tips:'
            '\n 1. Ensure your advertising packet is constructed correctly with both'
            '\n    the "Complete List of 16-bit Service UUIDs" advertising type (with'
            '\n    the Hubble UUID) and "Service Data" type included.'
            '\n 2. Ensure your device as advertising at all (if in doubt, try a BLE'
            '\n    scanning app on your phone)'
            '\n\nIf these do not resolve your issue please contact support@hubble.com.'
        )
    _validate_success()

    # Step 6: Validate encryption and detect EID type
    _validate_info("Validating encryption of received packets")
    pkt_to_ingest, dec_result, eid_label, _ = _detect_eid_type(decoded_key, pkts)
    if not pkt_to_ingest:
        _validate_error(
            'Unable to decrypt packet with given device key.'
            '\n\nDebug tips:'
            '\n 1. Ensure you entered the key correctly when running this script.'
            '\n 2. Check that your device is provisioned with this same key.'
            '\n 3. Check that your device-level encryption is working.'
            '\n\nIf these do not resolve your issue please contact support@hubble.com.'
        )
    _validate_success()
    if eid_label == UNIX_TIME:
        click.echo(f"       EID type: {UNIX_TIME} (day counter={dec_result.counter})")
    elif eid_label == DEVICE_UPTIME:
        click.echo(f"       EID type: DEVICE_UPTIME (counter={dec_result.counter})")
    else:
        click.echo("       EID type: AMBIGUOUS (resolved with both UNIX_TIME and DEVICE_UPTIME)")
        click.secho(
            "       NOTE: Multiple devices may be in BLE range with different configs,\n"
            "             or a very unlikely cryptographic coincidence. "
            "Check your device config.",
            bold=True,
        )

    # Step 7: Ingest + backend retrieval
    _validate_info("Ingesting packet into the backend")
    try:
        org.ingest_packet(pkt_to_ingest)
    except BackendError:
        _validate_error("Unable to ingest packet on the backend (not your fault)")
    _validate_success()

    _validate_info("Checking for packet in the backend")
    timestamp = pkt_to_ingest.timestamp
    backend_pkt = None
    for _ in range(10):
        time.sleep(1)
        backend_pkt = _get_pkt_from_be_with_timestamp(org, device, timestamp)
        if backend_pkt:
            break
    if not backend_pkt:
        _validate_error("Unable to retrieve packet from the backend")
    _validate_success()

    click.secho("\n[COMPLETE] All validation steps passed!", fg="green", bold=True)
    click.secho("Packet metadata:")
    click.secho(f'\tname:     "{backend_pkt.device_name}"')
    click.secho(f'\tpayload:  "{backend_pkt.payload}"')
    click.secho(f"\tsequence: {backend_pkt.sequence}")


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
    help="Encryption key (hex or base64; 16 bytes = AES-128-CTR, 32 bytes = AES-256-CTR)",
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
      hubblenetwork ready write-key --address AA:BB:CC:DD:EE:FF --key a562a2f7e4c62bed52ab09633878f62b
      hubblenetwork ready write-key -a AA:BB:CC:DD:EE:FF -k "q9vH3u2J4aN8Rw1KpZsO+A==" --format json
    """
    use_json = output_format.lower() == "json"

    try:
        key_bytes = _parse_key(key)
    except ValueError as e:
        if use_json:
            json_output = _format_ready_json_error(
                command="ready write-key",
                device_address=address,
                error=Exception(str(e)),
                duration_ms=0,
            )
            click.echo(json.dumps(json_output, indent=2))
        else:
            click.secho(f"[ERROR] {e}", fg="red", err=True)
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
def ready_write_config(address: str, eid_type: str, timeout: float, output_format: str):
    """Write device configuration (EID type) to a Hubble Ready device.

    Pool size is fixed at 128 for counter mode.

    This command validates configuration parameters locally and writes them to the
    Device Configuration characteristic.

    Examples:
      hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type utc
      hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type counter
    """
    import time
    import sys
    from .ready import write_config
    from .errors import BleError

    start_time = time.monotonic()

    try:
        result = write_config(address, eid_type, rotation_period=0, timeout=timeout)
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
                    success_result["pool_size"] = 128

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
                    click.echo("  Pool size: 128")
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


_PERIOD_EXPONENT_LABELS = {
    10: "≈17m",
    11: "≈34m",
    12: "≈1.1h",
    13: "≈2.3h",
    14: "≈4.6h",
    15: "≈9h",
}


def _format_period_exponent(n: int) -> str:
    """Human-readable duration label for a period exponent (period = 2^n seconds)."""
    label = _PERIOD_EXPONENT_LABELS.get(n)
    if label is not None:
        return label
    return f"{2 ** n}s" if n >= 0 else f"2^{n}s"


@org.command("register-device")
@click.option(
    "--encryption",
    "-e",
    type=str,
    default=None,
    show_default=False,
    help="Encryption type [AES-256-CTR, AES-128-CTR, AES-128-EAX, NONE]",
)
@click.option(
    "--counter-source",
    "-c",
    type=click.Choice(sorted([UNIX_TIME, DEVICE_UPTIME])),
    default=None,
    show_default=False,
    help="EID rotation counter source",
)
@click.option(
    "--period-seconds",
    type=int,
    default=None,
    show_default=False,
    help="EID rotation period in seconds (AES-128-EAX + DEVICE_UPTIME only).",
)
@click.option(
    "--period-exponent",
    type=int,
    default=None,
    show_default=False,
    help="EID rotation period exponent; period = 2^n seconds. Cloud accepts 10-15 (default 15).",
)
@pass_orgcfg
def register_device(org: Organization, encryption, counter_source, period_seconds, period_exponent) -> None:
    if period_seconds is not None and period_exponent is not None:
        raise click.UsageError("provide at most one of --period-seconds / --period-exponent")

    if encryption:
        click.secho(f'[INFO] Overriding default encryption, using "{encryption}"')
    if counter_source:
        click.secho(f'[INFO] EID rotation counter source: "{counter_source}"')
    if period_seconds is not None:
        click.secho(f'[INFO] EID rotation period: {period_seconds}s')
    if period_exponent is not None:
        click.secho(
            f'[INFO] EID rotation period exponent: {period_exponent} ({_format_period_exponent(period_exponent)})'
        )
    if (
        encryption == "AES-128-EAX"
        and counter_source == DEVICE_UPTIME
        and period_seconds is None
        and period_exponent is None
    ):
        click.secho(
            f'[INFO] Using default EID rotation period exponent: 15 ({_format_period_exponent(15)})'
        )

    click.secho(str(org.register_device(
        encryption=encryption,
        counter_source=counter_source,
        period_seconds=period_seconds,
        period_exponent=period_exponent,
    )))


@org.command("delete-device")
@click.argument("device-id", type=str)
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt.")
@pass_orgcfg
def delete_device(org: Organization, device_id: str, yes: bool) -> None:
    if not yes:
        click.confirm(
            f"Delete device {device_id}? This cannot be undone.",
            abort=True,
        )
    org.delete_device(device_id)
    click.echo(f"Device {device_id} deleted.")


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
@click.option(
    "--payload-format",
    "payload_format",
    type=click.Choice(["base64", "hex", "string"], case_sensitive=False),
    default="base64",
    show_default=True,
    help="Encoding format for packet payload",
)
@pass_orgcfg
def get_packets(
    org: Organization, device_id: str, output_format: str = "tabular", days: int = 7, payload_format: str = "base64"
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
    _print_packets(packets, output_format, payload_format)


# ---------------------------------------------------------------------------
# metrics -- Device metrics commands
# ---------------------------------------------------------------------------


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
def metrics(ctx, org_id, token) -> None:
    """Device metrics and analytics."""
    try:
        ctx.obj = Organization(org_id=org_id, api_token=token)
    except InvalidCredentialsError as e:
        raise click.BadParameter(str(e))


@metrics.command("devices")
@click.option(
    "--days",
    "-d",
    type=int,
    default=1,
    show_default=True,
    help="Number of days to look back",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format",
)
@pass_orgcfg
def metrics_devices(org: Organization, days: int, output_format: str) -> None:
    """Show device metrics (registered, active, never-active counts).

    Example:
      hubblenetwork metrics devices
      hubblenetwork metrics devices --days 7
      hubblenetwork metrics devices --days 30 -o json
    """
    data = org.device_metrics(days_back=days)

    if output_format == "json":
        click.echo(json.dumps(data, indent=2))
        return

    # Table output
    buckets = data.get("buckets", [])
    if buckets:
        headers = ["TIMESTAMP", "REGISTERED", "ACTIVE", "NEVER ACTIVE"]
        rows = [
            [
                b["timestamp"],
                b["registered_devices"],
                b["active_devices"],
                b["never_active_devices"],
            ]
            for b in buckets
        ]
        click.echo(tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        click.echo("No bucket data available.")

    click.echo("")
    click.echo("Totals:")
    click.echo(f"  Registered:   {data.get('total_registered_devices', 'N/A')}")
    click.echo(f"  Active:       {data.get('total_active_devices', 'N/A')}")
    click.echo(f"  Never Active: {data.get('total_never_active_devices', 'N/A')}")


# ---------------------------------------------------------------------------
# sat – Satellite (PlutoSDR) commands
# ---------------------------------------------------------------------------

_DOCKER_INSTALL_URL = "https://www.docker.com/get-started/"


def _docker_err_msg() -> str:
    url = _DOCKER_INSTALL_URL
    if sys.stderr.isatty():
        url = f"\x1b]8;;{url}\x1b\\{url}\x1b]8;;\x1b\\"
    return (
        f"Docker Desktop is required for satellite scanning. "
        f"Install from {url} and make sure it is running."
    )


@cli.group()
def sat() -> None:
    """Satellite (PlutoSDR) utilities."""


def _run_sat_scan(
    *,
    mock: bool,
    timeout: Optional[int],
    count: Optional[int],
    output_format: str,
    poll_interval: float,
    payload_format: str,
    debug: bool = False,
) -> None:
    """Shared implementation for ``sat scan`` and ``sat mock-scan``."""
    mode_label = "mock satellite receiver" if mock else "satellite receiver"

    printer_class = _SAT_STREAMING_PRINTERS.get(
        output_format.lower(), _SatStreamingTablePrinter
    )
    printer = printer_class(payload_format=payload_format)

    if debug:
        sat_logger = logging.getLogger("hubblenetwork.sat")
        sat_logger.setLevel(logging.DEBUG)
        sat_logger.addHandler(_handler)

    # Fail fast: verify Docker is available before printing anything.
    try:
        sat_mod.ensure_docker_available()
    except sat_mod.DockerError as exc:
        msg = str(exc) or _docker_err_msg()
        if printer.suppress_info_messages:
            click.echo(json.dumps({"error": msg}))
        else:
            click.secho(f"\n[ERROR] {msg}", fg="red", err=True)
        sys.exit(1)

    if not printer.suppress_info_messages:
        click.secho(
            f"[INFO] Starting {mode_label}... (Press Ctrl+C to stop)"
        )

    def _on_status(msg: str) -> None:
        if not printer.suppress_info_messages:
            click.secho(f"[INFO] {msg}", fg="cyan", err=True)

    _stop_msg_shown = [False]

    def _on_interrupt(sig, frame):
        if not _stop_msg_shown[0] and not printer.suppress_info_messages:
            click.secho(
                f"\n[INFO] Stopping {mode_label}...", fg="yellow", err=True
            )
            _stop_msg_shown[0] = True
        raise KeyboardInterrupt()

    old_handler = signal.signal(signal.SIGINT, _on_interrupt)
    error_occurred = False
    try:
        for pkt in sat_mod.scan(
            timeout=timeout, poll_interval=poll_interval, mock=mock,
            on_status=_on_status,
        ):
            printer.print_row(pkt)
            if count is not None and printer.packet_count >= count:
                break
    except sat_mod.DockerError as exc:
        error_occurred = True
        msg = str(exc) or _docker_err_msg()
        if printer.suppress_info_messages:
            click.echo(json.dumps({"error": msg}))
        else:
            click.secho(f"\n[ERROR] {msg}", fg="red", err=True)
        sys.exit(1)
    except sat_mod.SatelliteError as e:
        error_occurred = True
        if printer.suppress_info_messages:
            click.echo(json.dumps({"error": str(e)}))
        else:
            click.secho(f"\n[ERROR] {e}", fg="red", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, old_handler)
        printer.finalize()

        if not printer.suppress_info_messages and not error_occurred:
            click.echo("")
            click.secho(
                f"[INFO] Scanning stopped. {printer.packet_count} packet(s) received.",
                fg="yellow",
            )


def _sat_scan_options(fn):
    """Apply the common sat scan/mock-scan Click options."""
    for decorator in reversed([
        click.option("--timeout", "-t", type=int, show_default=False,
                     help="Timeout in seconds (default: no timeout)"),
        click.option("--count", "-n", type=int, default=None,
                     show_default=False, help="Stop after receiving N packets"),
        click.option("--format", "-o", "output_format",
                     type=click.Choice(["tabular", "json"], case_sensitive=False),
                     default="tabular", show_default=True,
                     help="Output format for packets"),
        click.option("--poll-interval", type=float, default=2.0,
                     show_default=True, help="Seconds between API polls"),
        click.option("--payload-format", "payload_format",
                     type=click.Choice(["base64", "hex", "string"],
                                       case_sensitive=False),
                     default="base64", show_default=True,
                     help="Encoding format for packet payload"),
        click.option("--debug", is_flag=True, default=False,
                     help="Enable debug logging to stderr"),
    ]):
        fn = decorator(fn)
    return fn


@sat.command("scan")
@_sat_scan_options
def sat_scan(**kwargs) -> None:
    """
    Start the satellite receiver and stream decoded packets.

    Requires Docker and a PlutoSDR device connected via USB.

    Example:
      hubblenetwork sat scan --timeout 30
      hubblenetwork sat scan -o json --timeout 10
      hubblenetwork sat scan -n 5
    """
    _run_sat_scan(mock=False, **kwargs)


@sat.command("mock-scan")
@_sat_scan_options
def sat_mock_scan(**kwargs) -> None:
    """
    Start the satellite receiver in mock mode and stream synthetic packets.

    Uses simulated data -- no PlutoSDR hardware required. Useful for testing
    the satellite scanning interface.

    Example:
      hubblenetwork sat mock-scan --timeout 30
      hubblenetwork sat mock-scan -o json -n 5
    """
    _run_sat_scan(mock=True, **kwargs)


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
    except click.ClickException as e:
        click.echo("", err=True)
        click.secho(f"Error: {e.format_message()}", fg="red", bold=True, err=True)
        return e.exit_code
    except Exception as e:  # safety net to avoid tracebacks in user CLI
        click.secho(f"Unexpected error: {e}", fg="red", err=True)
        return 2
    return 0


if __name__ == "__main__":
    # Forward command-line args (excluding the program name) to main()
    raise SystemExit(main())
