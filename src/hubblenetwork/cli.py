# hubblenetwork/cli.py
from __future__ import annotations

import base64
import binascii
import difflib
import functools
import json
import logging
import os
import signal
import sys
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from functools import partial
from typing import ClassVar

import click
from tabulate import tabulate

from hubblenetwork import (
    DEVICE_UPTIME,
    UNIX_TIME,
    DecryptedPacket,
    Device,
    EncryptedPacket,
    InvalidCredentialsError,
    Organization,
    cloud,
    decrypt,
    decrypt_eax,
    decrypt_satellite,
)
from hubblenetwork import ble as ble_mod
from hubblenetwork import ready as ready_mod
from hubblenetwork import sat as sat_mod
from hubblenetwork.crypto import find_time_counter_delta
from hubblenetwork.detect import (
    CtrCounterModeDetector,
    EaxExponentDetector,
    detect_eid_type,
)
from hubblenetwork.errors import BackendError
from hubblenetwork.packets import (
    AesEaxPacket,
    SatellitePacket,
    UnencryptedPacket,
    UnknownPacket,
)

# Set up logger for CLI (outputs to stderr)
logger = logging.getLogger(__name__)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
logger.addHandler(_handler)

# Symbol time length in ms
SYMBOL_TIME = 8.0

# Symbol time tolerance. With our envelope detection, we can expect the symbol
# to be off by 1/2 of the length of the symbol before that envelope
# reads the adjacent symbol, Any deviation from the nominal 8ms will see a dB
# loss, but the frequency will be correct
TIMING_TOLERANCE = 4.0

_TIMESTAMP_FORMAT = "%Y%m%d_%H%M%S"  # used to name default sat record/signal-report output files


def _default_iq_capture_name() -> str:
    return f"iq_capture_{datetime.now(timezone.utc).astimezone().strftime(_TIMESTAMP_FORMAT)}.npy"


def _default_signal_report_name() -> str:
    return f"signal_report_{datetime.now(timezone.utc).astimezone().strftime(_TIMESTAMP_FORMAT)}.txt"


# One entry per ``sat record`` / ``sat signal-report`` one-shot command, keyed
# by the sat.py function name to call: the in-progress status label, how to
# name the output file when --output is omitted, and the mode to open that file
# in. Looked up via getattr(sat_mod, mode) rather than storing the function
# directly, so tests that patch ``hubblenetwork.cli.sat_mod`` still take effect.
_ONE_SHOT_MODES = {
    "record": {
        "label": "Capturing IQ samples",
        "default_name": _default_iq_capture_name,
        "write_mode": "wb",
    },
    "signal_report": {
        "label": "Recording signal diagnostic",
        "default_name": _default_signal_report_name,
        "write_mode": "w",
    },
}


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


def _announce_detection(label: str | None, *, suppress: bool) -> None:
    """Print the one-shot ``[INFO] Detected:`` line for a fresh detection.

    ``label`` is set by the detector only on the first successful detection of a
    scan, so a no-op when it is None or output is suppressed (JSON mode).
    """
    if label and not suppress:
        click.secho(f"[INFO] Detected: {label}", fg="green", err=True)


def _format_payload(payload, fmt: str) -> str:
    """Format packet payload bytes for display."""
    if not isinstance(payload, bytes):
        return str(payload)
    if fmt == "auto":
        # Printable ASCII reads as text; anything else as hex, which is half the
        # width of \xNN escapes and is how firmware payloads are usually read.
        if payload and all(0x20 <= b < 0x7F for b in payload):
            return payload.decode("ascii")
        return payload.hex().upper()
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


# ---------------------------------------------------------------------------
# Streaming table presentation
#
# Hierarchy comes from space, weight and alignment first; color only enhances.
# Every element maps to a concrete mechanism: magnitude is bar length, state is
# a mark plus a semantic color, chrome is a dim rule.
# ---------------------------------------------------------------------------

_BAR_FRACTIONS = "▏▎▍▌▋▊▉"  # 1/8 .. 7/8 blocks
_SAT_PAYLOAD_WIDTH = 22
_BAR_CELLS = 5
_RSSI_FLOOR = -100  # empty bar at or below this dBm
_RSSI_CEIL = -40  # full bar at or above this dBm


def _signal_bar(rssi: int | None) -> str:
    """Render RSSI as a fixed-width bar. Length carries the magnitude."""
    if rssi is None:
        return " " * _BAR_CELLS
    span = _RSSI_CEIL - _RSSI_FLOOR
    frac = max(0.0, min(1.0, (rssi - _RSSI_FLOOR) / span))
    eighths = round(frac * _BAR_CELLS * 8)
    full, rem = divmod(eighths, 8)
    bar = "█" * full + (_BAR_FRACTIONS[rem - 1] if rem else "")
    return bar.ljust(_BAR_CELLS)


def _decrypt_mark(decrypt_status: str | None) -> str:
    """Decrypt state as a mark plus color. The mark alone carries it under NO_COLOR."""
    if decrypt_status == "ok":
        return click.style("✓", fg="green")
    if decrypt_status == "fail":
        return click.style("✗", fg="red")
    return " "


def _effective_payload_format(ctx, payload_format: str, is_tabular: bool) -> str:
    """Resolve the payload format actually used by the renderer.

    Tabular output reads better as text-or-hex, so it defaults to ``auto``. JSON
    keeps base64 so the machine contract stays byte-identical. An explicit
    ``--payload-format`` always wins.
    """
    explicit = (
        ctx.get_parameter_source("payload_format")
        == click.core.ParameterSource.COMMANDLINE
    )
    if is_tabular and not explicit:
        return "auto"
    return payload_format


def _scan_summary(
    count: int,
    elapsed: float,
    *,
    hidden: int = 0,
    decrypted: int | None = None,
    failed: int | None = None,
    extra: str | None = None,
    empty_hint: list[str] | None = None,
) -> None:
    """Close a scan with a declared result, on stderr so stdout stays data.

    An empty scan states what was checked and what to try next rather than
    reporting a bare zero.
    """
    secs = round(elapsed)
    click.echo("", err=True)
    if count == 0:
        click.secho(f"No packets in {secs}s.", bold=True, err=True, nl=False)
        click.echo(f" {empty_hint[0] if empty_hint else ''}", err=True)
        for line in (empty_hint or [])[1:]:
            click.secho("  " + line, dim=True, err=True)
        return

    parts = []
    # The tally must reconcile with the packet count shown alongside it.
    if decrypted is not None and failed is not None and (decrypted or failed):
        parts.append(f"{decrypted} decrypted, {failed} failed")
    if extra:
        parts.append(extra)
    parts.append(f"{secs}s")
    click.secho(f"{count} packets", bold=True, err=True, nl=False)
    click.secho("  ·  " + "  ·  ".join(parts), dim=True, err=True)
    if hidden:
        click.secho(
            f"  {hidden} packet(s) failed to decrypt and were hidden.  "
            "Show them:  --show-failed-decryption",
            dim=True,
            err=True,
        )


def _fit(text: str, width: int, *, nbytes: int | None = None) -> str:
    """Pad to width, or truncate with an explicit marker.

    A clipped cell must never read as the whole value, so truncation appends
    the real byte count (``+9B``) rather than an ellipsis.
    """
    if len(text) > width:
        tail = f"+{nbytes}B" if nbytes is not None else ">"
        text = text[: max(0, width - len(tail))] + tail
    return text.ljust(width)


# ---------------------------------------------------------------------------
# Help and error recovery
#
# Two rules govern everything below: help lists what actually exists (the
# command column is generated from the Click tree, so it can't drift), and no
# failure is a dead end -- every error names a command you can run next.
# ---------------------------------------------------------------------------

# Ordered so the cloud commands most people start with come first.
_GROUP_ORDER = ["org", "ble", "ready", "sat", "metrics"]

_GROUP_BLURB = {
    "org": "your devices in the Hubble Cloud",
    "ble": "nearby devices over Bluetooth",
    "ready": "provision a device over GATT",
    "sat": "satellite packets via PlutoSDR",
    "metrics": "fleet counts",
}

_START_HERE = [
    ("validate-credentials", "Confirm your credentials work"),
    ("org list-devices", "See what's registered"),
    ("ble scan --timeout 30", "Watch nearby devices report"),
    ("org get-packets <id>", "Read one device's packets"),
]

_HELP_COL = 35  # keeps the widest row ("org set-device-name <id> <name>") inside 80


def _invocation(path: list[str], cmd: click.Command) -> str:
    """`org get-packets <id>` -- the full command plus its required arguments."""
    parts = list(path)
    for p in cmd.params:
        if isinstance(p, click.Argument) and p.required:
            parts.append(p.metavar or f"<{p.name.replace('_', '-')}>")
    return " ".join(parts)


def _walk_commands(group: click.Group, path: list[str] | None = None):
    """Yield (path, leaf_command) for every leaf under `group`, depth-first."""
    path = path or []
    for name in group.list_commands(None):
        sub = group.get_command(None, name)
        if sub is None or getattr(sub, "hidden", False):
            continue
        if isinstance(sub, click.Group):
            yield from _walk_commands(sub, path + [name])
        else:
            yield path + [name], sub


def _command_index(root: click.Group) -> dict:
    """Map 'org list-devices' -> (path, command) for the whole tree."""
    return {" ".join(p): (p, c) for p, c in _walk_commands(root)}


def _root_group() -> click.Group:
    return cli


def _suggest_commands(name: str) -> tuple:
    """Find where `name` might have meant to go.

    Returns (paths, kind) where kind is "exact" when the name really exists
    elsewhere in the tree, or "close" for a spelling near-miss. Substring hits
    beat fuzzy ones, and the list is capped so it stays a pointer rather than a
    second menu.
    """
    index = _command_index(_root_group())
    exact = sorted(k for k, (p, _) in index.items() if p[-1] == name)
    if exact:
        return exact, "exact"
    leaves = {k: p[-1] for k, (p, _) in index.items()}
    contains = sorted(k for k, last in leaves.items() if name in last or last in name)
    if contains:
        return contains[:3], "close"
    close = difflib.get_close_matches(name, list(leaves.values()), n=3, cutoff=0.7)
    return sorted(k for k, last in leaves.items() if last in close)[:3], "close"


def _unknown_command_message(name: str) -> str:
    paths, kind = _suggest_commands(name)
    lines = [f"No such command '{name}'."]
    if paths:
        lines.append("")
        if len(paths) == 1:
            lines.append(
                "  Did you mean:  "
                + click.style(f"hubblenetwork {paths[0]}", fg="cyan")
            )
        else:
            lines.append(
                "  That command exists in more than one group:"
                if kind == "exact"
                else "  Did you mean one of:"
            )
            for p in paths:
                lines.append("    " + click.style(f"hubblenetwork {p}", fg="cyan"))
    return "\n".join(lines)


class HubbleGroup(click.Group):
    """A group whose help lists real invocations and whose errors point somewhere.

    Click only searches sibling commands when a name is unknown, so from the
    root it cannot see that `list-devices` lives under `org`. This searches the
    whole tree instead.
    """

    def resolve_command(self, ctx, args):
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError as exc:
            name = args[0] if args else ""
            # Only re-word the "no such command" case; leave real usage errors alone.
            if name and "No such command" in (exc.format_message() or ""):
                raise click.UsageError(_unknown_command_message(name), ctx=ctx) from None
            raise

    def _row(self, left: str, right: str) -> str:
        return "  " + left.ljust(_HELP_COL) + right

    def _base_path(self, ctx) -> list[str]:
        """This group's own path, so rows read `ble scan` not `scan`."""
        if ctx is None or ctx.parent is None:
            return []
        parts = (ctx.command_path or "").split()
        return parts[1:]  # drop the program name

    def format_commands(self, ctx, formatter) -> None:
        leaves = list(_walk_commands(self, self._base_path(ctx)))
        if not leaves:
            return
        nested = any(
            isinstance(self.get_command(ctx, n), click.Group)
            for n in self.list_commands(ctx)
        )

        if not nested:
            formatter.write("\n")
            formatter.write(click.style("Commands\n", bold=True))
            for path, cmd in leaves:
                formatter.write(
                    self._row(_invocation(path, cmd), cmd.get_short_help_str(60)) + "\n"
                )
            return

        formatter.write("\n")
        formatter.write(click.style("Start here\n", bold=True))
        for command, why in _START_HERE:
            formatter.write(self._row(command, click.style(why, dim=True)) + "\n")

        formatter.write("\n")
        formatter.write(click.style("Commands\n", bold=True))
        grouped: dict = {}
        loose: list[tuple] = []
        for path, cmd in leaves:
            if len(path) > 1:
                grouped.setdefault(path[0], []).append((path, cmd))
            else:
                loose.append((path, cmd))
        for name in _GROUP_ORDER:
            rows = grouped.get(name)
            if not rows:
                continue
            formatter.write("\n")
            formatter.write(
                "  "
                + click.style(name, fg="cyan")
                + click.style(f"  {_GROUP_BLURB.get(name, '')}", dim=True)
                + "\n"
            )
            for path, cmd in rows:
                formatter.write(
                    self._row("  " + _invocation(path, cmd), cmd.get_short_help_str(60))
                    + "\n"
                )
        if loose:
            formatter.write("\n")
            formatter.write("  " + click.style("general", fg="cyan") + "\n")
            for path, cmd in loose:
                formatter.write(
                    self._row("  " + _invocation(path, cmd), cmd.get_short_help_str(60))
                    + "\n"
                )

    def format_options(self, ctx, formatter) -> None:
        """Commands before options at the root: what to run matters more than how."""
        if ctx.parent is None:
            self.format_commands(ctx, formatter)
            opts = []
            for param in self.get_params(ctx):
                rv = param.get_help_record(ctx)
                if rv is not None:
                    opts.append(rv)
            if opts:
                formatter.write("\n")
                with formatter.section(click.style("Options", bold=True)):
                    formatter.write_dl(opts)
            return
        super().format_options(ctx, formatter)

    def format_epilog(self, ctx, formatter) -> None:
        super().format_epilog(ctx, formatter)
        if ctx.parent is None:
            formatter.write("\n")
            formatter.write(
                click.style("  Any command takes --help, e.g.  ", dim=True)
                + "hubblenetwork org get-packets --help\n"
            )


class GuidedArgument(click.Argument):
    """A positional argument that says how to find its value when omitted."""

    def __init__(self, *args, guidance: str | None = None, **kwargs):
        self.guidance = guidance
        super().__init__(*args, **kwargs)

    def process_value(self, ctx, value):
        if self.guidance and self.required and self.value_is_missing(value):
            label = self.metavar or self.name.upper()
            raise click.UsageError(
                f"Missing argument '{label}'.\n\n{self.guidance}", ctx=ctx
            )
        return super().process_value(ctx, value)


_FIND_DEVICE_ID = (
    "  Find a device ID with:\n"
    + "    "
    + click.style("hubblenetwork org list-devices", fg="cyan")
)


def _credentials_error(*, org_id: str | None, token: str | None) -> click.ClickException:
    """Build the credentials error. Not-set and rejected need different advice."""
    lines = ["No valid Hubble credentials.", ""]
    if not org_id or not token:
        missing = [
            n for n, v in (("HUBBLE_ORG_ID", org_id), ("HUBBLE_API_TOKEN", token)) if not v
        ]
        lines.append(f"  {' and '.join(missing)} not set. Set both:")
        lines.append(click.style("    export HUBBLE_ORG_ID=<your org id>", fg="cyan"))
        lines.append(click.style("    export HUBBLE_API_TOKEN=<your api token>", fg="cyan"))
        lines.append("")
        lines.append(click.style("  Or pass them per command:", dim=True))
        lines.append(
            click.style(
                "    hubblenetwork org --org-id <id> --token <token> list-devices",
                fg="cyan",
            )
        )
    else:
        lines.append("  Both PROD and TESTING rejected the org ID and token you gave.")
        lines.append(
            click.style("  They must be from the same environment, and the token must", dim=True)
        )
        lines.append(
            click.style("  belong to that org. Re-copy both from the Hubble dashboard.", dim=True)
        )
    lines.append(
        click.style("  Check them:  ", dim=True) + "hubblenetwork validate-credentials"
    )
    return click.ClickException("\n".join(lines))


def _get_env_or_fail(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise click.ClickException(
            f"{name} is not set.\n\n"
            + "  Set it, then rerun:\n"
            + "    "
            + click.style(f"export {name}=<value>", fg="cyan")
        )
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
    decrypt_status: str | None = None,
) -> dict:
    """Convert a packet to a dictionary for JSON serialization."""
    ts = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc).astimezone().strftime("%c")
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
    device_name: str | None = None,
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
    device_name: str | None = None,
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

    def print_row(self, pkt, decrypt_status: str | None = None) -> None:
        """Print a single packet. Override in subclasses."""
        raise NotImplementedError

    def finalize(self) -> None:
        """Called when scanning is complete. Override in subclasses if needed."""

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def suppress_info_messages(self) -> bool:
        """Return True to suppress info messages (e.g., for JSON output)."""
        return False


class _StreamingTablePrinter(_StreamingPrinterBase):
    """Print table rows as they arrive, printing header once.

    The default column set carries only what a person watches live: when the
    packet arrived, how strong it was, which device, which counter, and the
    payload. Forensic fields (epoch, protocol version, auth tag, nonce salt)
    move behind ``--debug``, matching the ``sat scan --debug`` precedent.
    """

    # (header, width, align). Sized to the data, not padded for looks.
    _TIME = ("TIME", 8, "<")
    _RSSI = ("RSSI", 4, ">")
    _BAR = ("", _BAR_CELLS, "<")
    _EPOCH = ("EPOCH", 10, ">")
    _VERSION = ("V", 1, ">")
    _EID = ("EID", 16, "<")
    _TAG = ("TAG", 8, "<")
    _COUNTER = ("CTR/SEQ", 7, ">")
    _SALT = ("SALT", 4, "<")
    _NET_ID = ("NET_ID", 10, ">")
    _COORDS = ("COORDINATES", 21, "<")
    _PAYLOAD = ("PAYLOAD", 26, "<")

    def __init__(
        self,
        payload_format: str = "base64",
        show_decrypt_status: bool = False,
        show_debug_cols: bool = False,
    ):
        super().__init__(show_decrypt_status=show_decrypt_status)
        self._header_printed = False
        self._cols: list[tuple] = []
        self._show_net_id = False
        self._show_coordinates = False
        self._payload_format = payload_format
        self._show_debug_cols = show_debug_cols

    def _determine_columns(self, pkt) -> list[tuple]:
        """Pick columns from the first packet seen.

        Unencrypted (version 1) packets have no EID or counter, so NET_ID takes
        that space instead of printing two columns of "-".
        """
        self._show_net_id = isinstance(pkt, UnencryptedPacket)
        self._show_coordinates = not pkt.location.fake

        cols: list[tuple] = [self._TIME]
        if self._show_debug_cols:
            cols.append(self._EPOCH)
        cols.extend([self._RSSI, self._BAR, self._VERSION])
        if self._show_net_id:
            cols.append(self._NET_ID)
        else:
            cols.extend([self._EID, self._COUNTER])
        if self._show_debug_cols:
            cols.extend([self._TAG, self._SALT])
        if self._show_coordinates:
            cols.append(self._COORDS)
        cols.append(self._PAYLOAD)
        return cols

    @property
    def _lead(self) -> str:
        """Left gutter. Reserves two cells for the decrypt mark when shown."""
        return "  " if self._show_decrypt_status else ""

    def _format_row(self, values: list[str]) -> str:
        cells = [
            v.rjust(w) if align == ">" else v.ljust(w)
            for v, (_, w, align) in zip(values, self._cols)
        ]
        return ("  " + " ".join(cells)).rstrip()

    def _make_separator(self) -> str:
        width = 2 + sum(w for _, w, _ in self._cols) + (len(self._cols) - 1)
        return click.style("─" * (width + len(self._lead)), dim=True)

    def print_row(self, pkt, decrypt_status: str | None = None) -> None:
        """Print a single packet row, printing header first if needed."""
        if not self._header_printed:
            self._cols = self._determine_columns(pkt)
            headers = [name for name, _, _ in self._cols]
            click.echo("")
            click.secho(self._lead + self._format_row(headers), bold=True)
            click.echo(self._make_separator())
            self._header_printed = True

        row: list[str] = [
            datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc)
            .astimezone()
            .strftime("%H:%M:%S")
        ]
        if self._show_debug_cols:
            row.append(str(pkt.timestamp))
        row.append("None" if pkt.rssi is None else str(pkt.rssi))
        row.append(_signal_bar(pkt.rssi))

        version = getattr(pkt, "protocol_version", None)
        row.append("-" if version is None else str(version))

        if self._show_net_id:
            row.append(
                str(pkt.network_id) if isinstance(pkt, UnencryptedPacket) else "-"
            )
        else:
            eid = getattr(pkt, "eid", None)
            row.append(f"{eid:x}" if eid is not None else "-")
            if isinstance(pkt, DecryptedPacket):
                ctr = pkt.counter if pkt.counter is not None else pkt.sequence
                row.append("-" if ctr is None else str(ctr))
            else:
                row.append("-")

        if self._show_debug_cols:
            auth_tag = getattr(pkt, "auth_tag", None)
            row.append(auth_tag.hex() if auth_tag is not None else "-")
            salt = getattr(pkt, "nonce_salt", None)
            row.append(salt.hex() if salt is not None else "-")

        if self._show_coordinates:
            loc = pkt.location
            row.append(f"{loc.lat:.6f},{loc.lon:.6f}")

        raw = _ctr_display_payload(pkt)
        payload = _format_payload(raw, self._payload_format)
        nbytes = len(raw) if isinstance(raw, bytes) else None
        row.append(_fit(payload or "-", self._PAYLOAD[1], nbytes=nbytes))

        prefix = (
            _decrypt_mark(decrypt_status) + " " if self._show_decrypt_status else ""
        )
        click.echo(prefix + self._format_row(row))
        self._packet_count += 1

    def finalize(self) -> None:
        if self._header_printed:
            click.echo(self._make_separator())


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

    def print_row(self, pkt, decrypt_status: str | None = None) -> None:
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
    decrypt_status: str | None = None,
    **_: object,
) -> dict:
    """Convert a SatellitePacket to a dictionary for JSON serialization."""
    ts = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc).astimezone().strftime("%c")
    data = {
        "device_id": pkt.device_id,
        "seq_num": pkt.seq_num,
        "device_type": pkt.device_type,
        "timestamp": pkt.timestamp,
        "datetime": ts,
        "rssi_dB": pkt.rssi_dB,
        "channel_num": pkt.channel_num,
        "freq_offset_hz": pkt.freq_offset_hz,
        "pdu_n_corr": pkt.pdu_n_corr,
        "header_n_corr": pkt.header_n_corr,
        "sym_mean_ms": pkt.sym_mean_ms,
        "gap_mean_ms": pkt.gap_mean_ms,
        "payload": _format_payload(pkt.payload, payload_format),
    }
    if pkt.auth_tag is not None:
        data["auth_tag"] = pkt.auth_tag.hex()
    if decrypt_status is not None:
        data["decrypt_status"] = decrypt_status
    return data


class _SatStreamingTablePrinter(_StreamingPrinterBase):
    """Print satellite packet rows as they arrive."""

    # (header, width, align), same system as the BLE table.
    _BASE_COLS: ClassVar[list[tuple]] = [
        ("TIME", 8, "<"),
        ("DEVICE_ID", 10, "<"),
        ("SEQ", 5, ">"),
        ("TYPE", 7, "<"),
        ("RSSI", 6, ">"),
        ("", _BAR_CELLS, "<"),
        ("CH", 3, ">"),
        ("FREQ_HZ", 9, ">"),
        ("PAYLOAD", _SAT_PAYLOAD_WIDTH, "<"),
    ]
    _DEBUG_COLS: ClassVar[list[tuple]] = [
        ("RS_CORR", 7, ">"),
        ("SYM_MS", 7, ">"),
        ("GAP_MS", 7, ">"),
    ]

    # Satellite RSSI sits well above BLE's range, so the bar gets its own scale.
    _RSSI_FLOOR_DB = 0.0
    _RSSI_CEIL_DB = 30.0

    def __init__(self, payload_format: str = "base64", show_decrypt_status: bool = False, show_debug_cols: bool = False):
        super().__init__(show_decrypt_status=show_decrypt_status)
        self._header_printed = False
        self._payload_format = payload_format
        self._show_debug_cols = show_debug_cols
        self._cols = list(self._BASE_COLS) + (self._DEBUG_COLS if show_debug_cols else [])

    @property
    def _lead(self) -> str:
        return "  " if self._show_decrypt_status else ""

    def _db_bar(self, rssi_db: float) -> str:
        span = self._RSSI_CEIL_DB - self._RSSI_FLOOR_DB
        frac = max(0.0, min(1.0, (rssi_db - self._RSSI_FLOOR_DB) / span))
        eighths = round(frac * _BAR_CELLS * 8)
        full, rem = divmod(eighths, 8)
        return ("█" * full + (_BAR_FRACTIONS[rem - 1] if rem else "")).ljust(_BAR_CELLS)

    def _format_row(self, values: list[str]) -> str:
        cells = [
            v.rjust(w) if align == ">" else v.ljust(w)
            for v, (_, w, align) in zip(values, self._cols)
        ]
        return ("  " + " ".join(cells)).rstrip()

    def _make_separator(self) -> str:
        width = 2 + sum(w for _, w, _ in self._cols) + (len(self._cols) - 1)
        return click.style("─" * (width + len(self._lead)), dim=True)

    def print_row(self, pkt: SatellitePacket, decrypt_status: str | None = None) -> None:
        if not self._header_printed:
            click.echo("")
            click.secho(
                self._lead + self._format_row([n for n, _, _ in self._cols]), bold=True
            )
            click.echo(self._make_separator())
            self._header_printed = True

        raw = pkt.payload
        payload = _format_payload(raw, self._payload_format)
        row: list[str] = [
            datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc)
            .astimezone()
            .strftime("%H:%M:%S"),
            pkt.device_id,
            str(pkt.seq_num),
            pkt.device_type,
            f"{pkt.rssi_dB:.1f}",
            self._db_bar(pkt.rssi_dB),
            str(pkt.channel_num),
            f"{pkt.freq_offset_hz:.1f}",
            _fit(
                payload or "-",
                _SAT_PAYLOAD_WIDTH,
                nbytes=len(raw) if isinstance(raw, bytes) else None,
            ),
        ]
        if self._show_debug_cols:
            rs = "-"
            if pkt.pdu_n_corr is not None and pkt.header_n_corr is not None:
                rs = str(pkt.pdu_n_corr + pkt.header_n_corr)
            row.append(rs)
            row.append(f"{pkt.sym_mean_ms:.2f}" if pkt.sym_mean_ms is not None else "-")
            row.append(f"{pkt.gap_mean_ms:.2f}" if pkt.gap_mean_ms is not None else "-")

        prefix = (
            _decrypt_mark(decrypt_status) + " " if self._show_decrypt_status else ""
        )
        click.echo(prefix + self._format_row(row))

        if (
            self._show_debug_cols
            and pkt.sym_mean_ms is not None
            and abs(pkt.sym_mean_ms - SYMBOL_TIME) > TIMING_TOLERANCE
        ):
            click.secho(
                f"{self._lead}  ! timing off: symbol {pkt.sym_mean_ms:.2f} ms, "
                f"expected {SYMBOL_TIME:.2f} ms",
                fg="yellow",
            )
        self._packet_count += 1

    def finalize(self) -> None:
        if self._header_printed:
            click.echo(self._make_separator())


_SAT_STREAMING_PRINTERS = {
    "tabular": _SatStreamingTablePrinter,
    "json": partial(_StreamingJsonPrinter, to_dict_fn=_sat_packet_to_dict),
}


def _print_packets_tabular(pkts: list, payload_format: str = "base64") -> None:
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
        ts = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc).astimezone().strftime("%c")
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
        ts = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc).astimezone().strftime("%c")
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
    click.echo(f"tags: {dev.tags!s}, ", nl=False)
    ts = datetime.fromtimestamp(dev.created_ts, tz=timezone.utc).astimezone().strftime("%c")
    click.echo(f'created: "{ts}", ', nl=False)
    click.echo(f"active: {dev.active!s}", nl=False)
    if dev.key:
        click.secho(f', key: "{dev.key}"')
    else:
        click.echo("")


# ---------------------------------------------------------------------------
# org streaming tables
#
# Same column system as the BLE/satellite scan tables: fixed widths sized to
# the data, one rule above and below, magnitude as bar length, chrome and
# summaries on stderr so stdout stays data.
# ---------------------------------------------------------------------------


class _OrgTablePrinter:
    """Emit a fixed-width table row by row, writing the header on first use."""

    def __init__(self, cols: list[tuple]):
        self._cols = cols
        self._header_printed = False
        self.count = 0

    def _line(self, values: list[str]) -> str:
        cells = [
            v.rjust(w) if align == ">" else v.ljust(w)
            for v, (_, w, align) in zip(values, self._cols)
        ]
        return ("  " + " ".join(cells)).rstrip()

    def _rule(self) -> str:
        width = 2 + sum(w for _, w, _ in self._cols) + (len(self._cols) - 1)
        return click.style("─" * width, dim=True)

    def row(self, values: list[str]) -> None:
        if not self._header_printed:
            click.secho(self._line([n for n, _, _ in self._cols]), bold=True)
            click.echo(self._rule())
            self._header_printed = True
        click.echo(self._line(values))
        self.count += 1

    def finalize(self) -> None:
        if self._header_printed:
            click.echo(self._rule())


def _org_heading(label: str, subject: str, detail: str = "") -> None:
    """One-line context header, on stderr so stdout stays data."""
    click.echo("", err=True)
    click.echo(
        click.style(label, fg="cyan") + f"  {subject}"
        + (click.style(f"  ·  {detail}", dim=True) if detail else ""),
        err=True,
    )


def _org_summary(head: str, details: list[str], notes: list[str] | None = None) -> None:
    """Declared result plus fine print, on stderr."""
    click.echo("", err=True)
    click.secho(head, bold=True, err=True, nl=False)
    if details:
        click.secho("  ·  " + "  ·  ".join(details), dim=True, err=True)
    else:
        click.echo("", err=True)
    for note in notes or []:
        click.secho("  " + note, dim=True, err=True)


def _days_phrase(days: int) -> str:
    return "last 1 day" if days == 1 else f"last {days} days"


_PACKET_PROGRESS_AFTER = 1.0  # seconds of silence before the first progress line


class _FetchProgress:
    """Report page-by-page fetch progress on stderr once the wait is noticeable.

    Nielsen's response-time limits, ported: stay silent under ~1s, name the
    verb past ~1s, show a real count past ~10s. A busy device can take 15s
    before the first page renders, which used to look like a hang.
    """

    def __init__(self, noun: str, *, enabled: bool):
        self._noun = noun
        self._enabled = enabled
        self._start = time.monotonic()
        self._shown = False

    def page(self, page: int, total: int) -> None:
        if not self._enabled:
            return
        if time.monotonic() - self._start < _PACKET_PROGRESS_AFTER:
            return
        click.secho(
            f"  fetching page {page}  ·  {total:,} {self._noun} so far"
            "  ·  Ctrl+C to stop",
            dim=True,
            err=True,
        )
        self._shown = True

    @property
    def shown(self) -> bool:
        return self._shown


def _get_version() -> str:
    """Return package version, with fallback for development installs."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("pyhubblenetwork")
    except PackageNotFoundError:
        return "dev"


@click.group(
    cls=HubbleGroup, context_settings={"help_option_names": ["-h", "--help"]}
)
@click.version_option(version=_get_version(), prog_name="hubblenetwork")
def cli() -> None:
    """Talk to Hubble Network IoT devices over Bluetooth and satellite, and to
    your devices in the Hubble Cloud."""
    # top-level group; subcommands are added below


@cli.command("validate-credentials", short_help="Check that your API credentials work")
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
    """Check that your API credentials work.

    Exits 1 when they do not, so scripts can branch on it.

    \b
    Example:
      hubblenetwork validate-credentials
      hubblenetwork validate-credentials --org-id <id> --token <token>
    """
    credentials = cloud.Credentials(org_id, token)
    env = cloud.get_env_from_credentials(credentials)
    if env:
        click.echo(f'Valid credentials (env="{env.name}")')
        return
    raise _credentials_error(org_id=org_id, token=token)


@cli.group(cls=HubbleGroup)
def ble() -> None:
    """Listen to nearby Hubble devices over Bluetooth."""
    # subgroup for BLE-related commands


@ble.command("detect", short_help="Identify which EID mode a key uses")
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
    timeout: int | None = None,
    key: str | None = None,
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

    ctr_detector = CtrCounterModeDetector(
        auto_detect=auto_detect_ctr,
        fixed_counter_mode=counter_mode,
        days=days,
        key_len=len(decoded_key),
    )
    eax_detector = EaxExponentDetector(
        auto_detect=auto_detect_eax, fixed_exponent=period_exponent
    )

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
        except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
            logger.error(f"BLE scanning error: {e}")
            _output_error(f"BLE scanning error: {e!s}")
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
            d = eax_detector.decrypt(
                decrypt_fn=lambda exp, pkt=pkt: decrypt_eax(
                    decoded_key, pkt, period_exponent=exp
                ),
                cache_key=pkt.eid,
            )
            _announce_detection(d.label, suppress=use_json)
            decrypted_pkt = d.result
        elif isinstance(pkt, EncryptedPacket):
            d = ctr_detector.decrypt(
                decrypt_fn=lambda pkt=pkt, **kw: decrypt(decoded_key, pkt, **kw),
                cache_key=pkt.eid,
            )
            _announce_detection(d.label, suppress=use_json)
            decrypted_pkt = d.result
        # UnencryptedPacket and UnknownPacket fall through — keep scanning.

        if decrypted_pkt:
            # If we can decrypt it, output success
            datetime_str = datetime.fromtimestamp(decrypted_pkt.timestamp, tz=timezone.utc).astimezone().strftime(
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


@ble.command("scan", short_help="Stream beacon packets from nearby devices")
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
    type=click.Choice(["auto", "base64", "hex", "string"], case_sensitive=False),
    default="base64",
    show_default=True,
    help=(
        "Encoding format for packet payload. Tabular output defaults to 'auto' "
        "(printable ASCII as text, otherwise hex); JSON always defaults to base64."
    ),
)
@click.option(
    "--show-failed-decryption",
    is_flag=True,
    default=False,
    help="Show encrypted packets that fail decryption/authentication with the provided key. Adds a ✓/✗ decrypt mark to each row.",
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Add forensic columns to tabular output: EPOCH, TAG, SALT.",
)
@click.pass_context
def ble_scan(
    ctx,
    timeout: int | None = None,
    count: int | None = None,
    network_id: int | None = None,
    ingest: bool = False,
    key: str | None = None,
    days: int = 2,
    counter_mode: str = "UNIX_TIME",
    period_exponent: int = 0,
    output_format: str = "tabular",
    payload_format: str = "base64",
    show_failed_decryption: bool = False,
    debug: bool = False,
) -> None:
    """
    Scan for UUID 0xFCA6 and print packets as they are found.

    Automatically detects encrypted vs unencrypted protocol packets.

    \b
    Example:
      hubblenetwork ble scan --timeout 30
      hubblenetwork ble scan --key "a562a2f7e4c62bed52ab09633878f62b" --timeout 60
      hubblenetwork ble scan -o json --timeout 10
      hubblenetwork ble scan -n 5              # Stop after 5 packets
      hubblenetwork ble scan --network-id 4378792717
      hubblenetwork ble scan --debug           # Add EPOCH/TAG/SALT columns
    """
    if counter_mode == DEVICE_UPTIME:
        if not key:
            raise click.UsageError("--counter-mode DEVICE_UPTIME requires --key")
        days_source = ctx.get_parameter_source("days")
        if days_source == click.core.ParameterSource.COMMANDLINE:
            raise click.UsageError(
                "--counter-mode DEVICE_UPTIME and --days are mutually exclusive"
            )

    is_tabular = output_format.lower() == "tabular"
    # Get the appropriate streaming printer
    printer_class = _STREAMING_PRINTERS.get(
        output_format.lower(), _StreamingTablePrinter
    )
    printer = printer_class(
        payload_format=_effective_payload_format(ctx, payload_format, is_tabular),
        show_decrypt_status=show_failed_decryption,
        **({"show_debug_cols": debug} if is_tabular else {}),
    )

    if not printer.suppress_info_messages:
        click.echo(
            "\nScanning for Hubble devices  " + click.style("Ctrl+C to stop", dim=True),
            err=True,
        )

    if ingest:
        org = Organization(
            org_id=_get_env_or_fail("HUBBLE_ORG_ID"),
            api_token=_get_env_or_fail("HUBBLE_API_TOKEN"),
        )

    start = time.monotonic()
    deadline = None if timeout is None else start + timeout

    # Pre-decode the key if provided
    decoded_key: bytearray | None = None
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

    ctr_detector = CtrCounterModeDetector(
        auto_detect=auto_detect_ctr,
        fixed_counter_mode=counter_mode,
        days=days,
        key_len=len(decoded_key) if decoded_key is not None else 0,
    )
    eax_detector = EaxExponentDetector(
        auto_detect=auto_detect_eax, fixed_exponent=period_exponent
    )

    hidden_failures = 0
    decrypt_ok = 0
    decrypt_fail = 0
    rssis: list[int] = []

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

            # When a key is supplied the user only wants packets the key can
            # validly decrypt. Version-1 packets are never encrypted and
            # unknown versions can't be decrypted, so skip both entirely.
            if decoded_key is not None and isinstance(
                pkt, (UnencryptedPacket, UnknownPacket)
            ):
                continue

            # Unencrypted packets: apply network_id filter, print directly
            if isinstance(pkt, UnencryptedPacket):
                if network_id is not None and pkt.network_id != network_id:
                    continue
                rssis.append(pkt.rssi)
                printer.print_row(pkt)
            # AES-EAX packets: decrypt if key provided, else show raw fields
            elif isinstance(pkt, AesEaxPacket):
                if decoded_key:
                    d = eax_detector.decrypt(
                        decrypt_fn=lambda exp, pkt=pkt: decrypt_eax(
                            decoded_key, pkt, period_exponent=exp
                        ),
                        cache_key=pkt.eid,
                    )
                    _announce_detection(
                        d.label, suppress=printer.suppress_info_messages
                    )
                    decrypted_pkt = d.result
                    if decrypted_pkt:
                        decrypt_ok += 1
                        rssis.append(pkt.rssi)
                        printer.print_row(decrypted_pkt, decrypt_status="ok")
                    elif show_failed_decryption:
                        decrypt_fail += 1
                        rssis.append(pkt.rssi)
                        printer.print_row(pkt, decrypt_status="fail")
                    else:
                        hidden_failures += 1
                else:
                    rssis.append(pkt.rssi)
                    printer.print_row(pkt)
            elif isinstance(pkt, EncryptedPacket):
                if decoded_key:
                    d = ctr_detector.decrypt(
                        decrypt_fn=lambda pkt=pkt, **kw: decrypt(decoded_key, pkt, **kw),
                        cache_key=pkt.eid,
                    )
                    _announce_detection(
                        d.label, suppress=printer.suppress_info_messages
                    )
                    decrypted_pkt = d.result
                    if decrypted_pkt:
                        decrypt_ok += 1
                        rssis.append(pkt.rssi)
                        printer.print_row(decrypted_pkt, decrypt_status="ok")
                        if ingest:
                            org.ingest_packet(pkt)
                    elif show_failed_decryption:
                        decrypt_fail += 1
                        rssis.append(pkt.rssi)
                        printer.print_row(pkt, decrypt_status="fail")
                    else:
                        hidden_failures += 1
                else:
                    rssis.append(pkt.rssi)
                    printer.print_row(pkt)
            elif isinstance(pkt, UnknownPacket):
                rssis.append(pkt.rssi)
                printer.print_row(pkt)
    except KeyboardInterrupt:
        pass  # Just exit the loop, cleanup happens below
    finally:
        # Allow printer to finalize (e.g., close JSON array)
        printer.finalize()

        if not printer.suppress_info_messages:
            extra = None
            if rssis:
                extra = f"RSSI {max(rssis)} to {min(rssis)} dBm"
            _scan_summary(
                printer.packet_count,
                time.monotonic() - start,
                hidden=hidden_failures,
                decrypted=decrypt_ok,
                failed=decrypt_fail,
                extra=extra,
                empty_hint=[
                    "Nothing advertising on UUID 0xFCA6 nearby.",
                    "Check the device is powered and advertising, that Bluetooth is on,",
                    "then widen the window:  hubblenetwork ble scan --timeout 60",
                ],
            )


@ble.command("check-time", short_help="Check a device's clock against real UTC")
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
    timeout: int | None = None, key: str | None = None, json_output: bool = False
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

        ts = datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc).astimezone().strftime("%c")

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


@ble.command("validate", short_help="End-to-end health check on one device")
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
    pkt_to_ingest, dec_result, eid_label, _ = detect_eid_type(decoded_key, pkts)
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


@cli.group(cls=HubbleGroup)
def ready() -> None:
    """Provision a Hubble Ready device over a GATT connection."""


@ready.command("scan", short_help="Find Hubble Ready devices to provision")
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
def ready_scan(timeout: float = 10.0, output_format: str = "tabular", address: str | None = None) -> None:
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
    devices_found: list[ready_mod.HubbleReadyDevice] = []
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
    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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
    devices: list[ready_mod.HubbleReadyDevice],
) -> ready_mod.HubbleReadyDevice | None:
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


@ready.command("info", short_help="Show every characteristic on a device")
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
    address: str | None = None, timeout: float = 10.0, output_format: str = "tabular"
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
        except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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
    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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


@ready.command("read-status", short_help="Read the device's status flags")
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
    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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


@ready.command("read-key-info", short_help="Read which key and cipher are loaded")
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
    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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


@ready.command("read-config", short_help="Read the EID rotation configuration")
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
    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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


@ready.command("read-time", short_help="Read the device's clock")
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
    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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
        timestamp_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).astimezone().isoformat()
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
    timestamp_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).astimezone().isoformat()
    timestamp_human = datetime.fromtimestamp(timestamp, tz=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    click.echo(f"  Unix Timestamp: {timestamp}")
    click.echo(f"  ISO 8601:       {timestamp_iso}")
    click.echo(f"  Human:          {timestamp_human}")


@ready.command("write-key", short_help="Load an encryption key onto a device")
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
    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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


@ready.command("write-config", short_help="Set the EID rotation configuration")
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
    import sys
    import time

    from .errors import BleError
    from .ready import write_config

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

    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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


@ready.command("write-time", short_help="Set the device's clock")
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
def ready_write_time(address: str, timestamp: int | None, timeout: float, output_format: str):
    """Write epoch time to a Hubble Ready device.

    This command writes a Unix timestamp to the Epoch Time characteristic.
    If no timestamp is provided, the current time is used.

    Examples:
      hubblenetwork ready write-time --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready write-time --address AA:BB:CC:DD:EE:FF --timestamp 1735603200
    """
    import sys
    import time
    from datetime import datetime, timezone

    from .errors import BleError
    from .ready import write_time

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

    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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


@ready.command("provision", short_help="Register and configure a device fully")
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
    org_id: str | None = None,
    token: str | None = None,
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
    except Exception as e:  # noqa: BLE001 - top-level CLI boundary: report and exit non-zero
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


class _LazyOrg:
    """Defer `Organization` construction until a command body actually needs it.

    Building it eagerly in the group callback fired two network calls before
    Click could print `--help`, so `org <sub> --help` failed with exit 2 for
    anyone without valid credentials.
    """

    def __init__(self, org_id: str | None, token: str | None) -> None:
        self._org_id = org_id
        self._token = token
        self._org: Organization | None = None

    def resolve(self) -> Organization:
        if self._org is None:
            try:
                self._org = Organization(org_id=self._org_id, api_token=self._token)
            except InvalidCredentialsError:
                raise _credentials_error(
                    org_id=self._org_id, token=self._token
                ) from None
        return self._org


def pass_orgcfg(fn):
    """Pass the resolved `Organization` as the first argument."""

    @click.pass_context
    @functools.wraps(fn)
    def wrapper(ctx, *args, **kwargs):
        holder = ctx.find_object(_LazyOrg)
        if holder is None:  # direct invocation in tests
            holder = _LazyOrg(None, None)
        return fn(holder.resolve(), *args, **kwargs)

    return wrapper


@cli.group(cls=HubbleGroup)
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
    """Manage your devices and packets in the Hubble Cloud."""
    # Credentials are resolved lazily so `--help` never needs a network call.
    ctx.obj = _LazyOrg(org_id, token)


@org.command("info", short_help="Show your organization and environment")
@pass_orgcfg
def info(org: Organization) -> None:
    """
    Show this organization's ID, name, and API environment.

    \b
    Example:
      hubblenetwork org info
    """
    click.echo("")
    click.secho(org.name, bold=True)
    click.echo("  " + click.style("ID  ", dim=True) + f"  {org.org_id}")
    click.echo(
        "  "
        + click.style("Env ", dim=True)
        + f"  {org.env.name}"
        + click.style(f"  ·  {org.env.url}", dim=True)
    )


_DEVICE_COLS = [
    ("ID", 36, "<"),
    ("NAME", 18, "<"),
    ("CREATED", 10, "<"),
    ("ACTIVE", 6, "<"),
]

_PKT_TIME = ("TIME", 14, "<")
_PKT_EPOCH = ("EPOCH", 10, ">")
_PKT_RSSI = ("RSSI", 4, ">")
_PKT_BAR = ("", _BAR_CELLS, "<")
_PKT_CTR = ("CTR", 6, ">")
_PKT_SEQ = ("SEQ", 5, ">")
_PKT_COORDS = ("COORDINATES", 21, "<")
_PKT_PAYLOAD = ("PAYLOAD", 26, "<")


def _stream_packets_tabular(
    org: Organization,
    device: Device,
    *,
    days: int,
    ctx,
    payload_format: str,
    limit: int,
    debug: bool,
) -> None:
    """Render backend packets row by row as pages arrive."""
    fmt = _effective_payload_format(ctx, payload_format, True)
    _org_heading("Packets", device.id, _days_phrase(days))

    progress = _FetchProgress("packets", enabled=True)
    printer: _OrgTablePrinter | None = None
    rssis: list[int] = []
    truncated = False
    interrupted = False

    try:
        for pkt in org.iter_packets(device, days=days, on_page=progress.page):
            if limit and printer is not None and printer.count >= limit:
                truncated = True
                break
            if printer is None:
                cols = [_PKT_TIME]
                if debug:
                    cols.append(_PKT_EPOCH)
                cols.extend([_PKT_RSSI, _PKT_BAR])
                if debug:
                    cols.extend([_PKT_CTR, _PKT_SEQ])
                if not pkt.location.fake:
                    cols.append(_PKT_COORDS)
                cols.append(_PKT_PAYLOAD)
                printer = _OrgTablePrinter(cols)

            row = [
                datetime.fromtimestamp(pkt.timestamp, tz=timezone.utc)
                .astimezone()
                .strftime("%m-%d %H:%M:%S")
            ]
            if debug:
                row.append(str(pkt.timestamp))
            row.append("None" if pkt.rssi is None else str(pkt.rssi))
            row.append(_signal_bar(pkt.rssi))
            if debug:
                row.append("-" if pkt.counter is None else str(pkt.counter))
                row.append("-" if pkt.sequence is None else str(pkt.sequence))
            if not pkt.location.fake:
                row.append(f"{pkt.location.lat:.6f},{pkt.location.lon:.6f}")
            payload = _format_payload(pkt.payload, fmt)
            row.append(
                _fit(
                    payload or "-",
                    _PKT_PAYLOAD[1],
                    nbytes=len(pkt.payload) if isinstance(pkt.payload, bytes) else None,
                )
            )
            printer.row(row)
            if pkt.rssi is not None:
                rssis.append(pkt.rssi)
    except KeyboardInterrupt:
        interrupted = True

    if printer is None:
        _org_summary(
            f"No packets in the {_days_phrase(days)}.",
            [],
            [
                "The device is registered but hasn't reported in this window.",
                f"Widen it:  hubblenetwork org get-packets {device.id} --days {days * 3}",
            ],
        )
        return

    printer.finalize()
    details = []
    if rssis:
        details.append(f"RSSI {max(rssis)} to {min(rssis)} dBm")
    details.append(_days_phrase(days))
    notes = []
    if truncated:
        notes.append(f"Stopped at --limit {limit}.  All of them:  drop --limit")
    elif interrupted:
        notes.append("Stopped early by Ctrl+C. Rerun without interrupting for the full window.")
    _org_summary(f"{printer.count:,} packets", details, notes)


def _device_to_dict(dev: Device) -> dict:
    data = {
        "id": dev.id,
        "name": dev.name,
        "tags": dev.tags,
        "created": datetime.fromtimestamp(dev.created_ts, tz=timezone.utc)
        .astimezone()
        .isoformat(),
        "created_ts": dev.created_ts,
        "active": dev.active,
    }
    if dev.key:
        data["key"] = base64.b64encode(dev.key).decode("ascii")
    return data


@org.command("list-devices", short_help="List every registered device")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format for devices",
)
@click.option(
    "--limit",
    "-n",
    type=int,
    default=0,
    show_default=False,
    help="Stop after N devices (default: no limit)",
)
@pass_orgcfg
def list_devices(org: Organization, output_format: str = "tabular", limit: int = 0) -> None:
    """
    List every device registered in this organization.

    Devices stream as pages arrive, so the first rows appear without waiting
    for the last page. Tags shared by every device are reported once in the
    summary instead of on each row.

    \b
    Example:
      hubblenetwork org list-devices
      hubblenetwork org list-devices -f json
      hubblenetwork org list-devices -n 20
    """
    is_tabular = output_format.lower() == "tabular"
    if is_tabular:
        _org_heading("Devices", org.name)

    progress = _FetchProgress("devices", enabled=is_tabular)
    printer = _OrgTablePrinter(_DEVICE_COLS) if is_tabular else None

    tag_sets: set = set()
    unnamed = 0
    inactive = 0
    collected: list[dict] = []
    truncated = False

    try:
        for dev in org.iter_devices(on_page=progress.page):
            if limit and (printer.count if printer else len(collected)) >= limit:
                truncated = True
                break
            tag_sets.add(tuple(sorted((dev.tags or {}).items())))
            if not dev.name:
                unnamed += 1
            if not dev.active:
                inactive += 1
            if printer:
                printer.row([
                    dev.id,
                    _fit(dev.name or "-", 18),
                    datetime.fromtimestamp(dev.created_ts, tz=timezone.utc)
                    .astimezone()
                    .strftime("%Y-%m-%d"),
                    "yes" if dev.active else "no",
                ])
            else:
                collected.append(_device_to_dict(dev))
    except KeyboardInterrupt:
        truncated = True

    if not is_tabular:
        click.echo(json.dumps(collected, indent=2))
        return

    printer.finalize()
    shown = printer.count
    if shown == 0:
        _org_summary(
            "No devices registered.",
            [],
            ["Register one:  hubblenetwork org register-device"],
        )
        return

    details = []
    notes = []
    if truncated:
        # Only report what was actually counted; org-wide tallies are unknown here.
        head = f"{shown} devices shown"
        notes.append("More were not listed.  All of them:  drop --limit")
    else:
        head = f"{shown} devices"
        if unnamed:
            details.append(f"{unnamed} unnamed")
        details.append(f"{inactive} inactive" if inactive else "all active")
        if len(tag_sets) == 1:
            only = next(iter(tag_sets))
            if only:
                details.append(
                    "tags: " + ", ".join(f"{k}={v}" for k, v in only)
                )
    _org_summary(head, details, notes)


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


@org.command("register-device", short_help="Register a new device and get its key")
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


@org.command("delete-device", short_help="Delete a device from your organization")
@click.argument(
    "device-id", type=str, metavar="<id>",
    cls=GuidedArgument, guidance=_FIND_DEVICE_ID,
)
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


@org.command("set-device-name", short_help="Rename a registered device")
@click.argument(
    "device-id", type=str, metavar="<id>",
    cls=GuidedArgument, guidance=_FIND_DEVICE_ID,
)
@click.argument(
    "name", type=str, metavar="<name>",
    cls=GuidedArgument,
    guidance="  The new name to give the device, for example:\n    " + click.style("hubblenetwork org set-device-name <id> field-unit-7", fg="cyan"),
)
@pass_orgcfg
def set_device_name(org: Organization, device_id: str, name: str) -> None:
    click.secho(str(org.set_device_name(device_id, name)))


@org.command("get-packets", short_help="Read a device's packets from the cloud")
@click.argument(
    "device-id", type=str, metavar="<id>",
    cls=GuidedArgument, guidance=_FIND_DEVICE_ID,
)
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
    type=click.Choice(["auto", "base64", "hex", "string"], case_sensitive=False),
    default="base64",
    show_default=True,
    help=(
        "Encoding format for packet payload. Tabular output defaults to 'auto' "
        "(printable ASCII as text, otherwise hex); json and csv default to base64."
    ),
)
@click.option(
    "--limit",
    "-n",
    type=int,
    default=0,
    show_default=False,
    help="Stop after N packets (default: no limit)",
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Add forensic columns to tabular output: EPOCH, CTR, SEQ.",
)
@click.pass_context
@pass_orgcfg
def get_packets(
    org: Organization,
    ctx,
    device_id: str,
    output_format: str = "tabular",
    days: int = 7,
    payload_format: str = "base64",
    limit: int = 0,
    debug: bool = False,
) -> None:
    """
    Retrieve and display packets for a device.

    Tabular output streams as pages arrive, so the first rows appear without
    waiting for the whole window to download. A busy device can return tens of
    thousands of packets; Ctrl+C stops early and still prints a summary.

    \b
    Example:
      hubblenetwork org get-packets DEVICE_ID
      hubblenetwork org get-packets DEVICE_ID -o json
      hubblenetwork org get-packets DEVICE_ID --format csv --days 30
      hubblenetwork org get-packets DEVICE_ID -n 50 --debug
    """
    device = Device(id=device_id)
    is_tabular = output_format.lower() == "tabular"

    # json and csv keep their exact byte output, so they buffer as before.
    if not is_tabular:
        packets = list(org.iter_packets(device, days=days))
        if limit:
            packets = packets[:limit]
        _print_packets(packets, output_format, payload_format)
        return

    _stream_packets_tabular(
        org, device, days=days, ctx=ctx,
        payload_format=payload_format, limit=limit, debug=debug,
    )


# ---------------------------------------------------------------------------
# metrics -- Device metrics commands
# ---------------------------------------------------------------------------


@cli.group(cls=HubbleGroup)
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
    """Fleet-level device counts."""
    # Credentials are resolved lazily so `--help` never needs a network call.
    ctx.obj = _LazyOrg(org_id, token)


@metrics.command("devices", short_help="Count registered, active and dark devices")
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


def _report_sat_error(exc: Exception, *, suppress_info_messages: bool = False) -> None:
    """Print a ``sat`` command's DockerError/SatelliteError and exit(1).

    A ``DockerError`` with no message (Docker isn't installed at all) falls
    back to the install hint. When *suppress_info_messages* is set (JSON
    output mode) the error is emitted as a ``{"error": ...}`` JSON line
    instead of a colored ``[ERROR]`` line to stderr.
    """
    if isinstance(exc, sat_mod.DockerError):
        msg = str(exc) or _docker_err_msg()
    else:
        msg = str(exc)
    if suppress_info_messages:
        click.echo(json.dumps({"error": msg}))
    else:
        click.secho(f"\n[ERROR] {msg}", fg="red", err=True)
    sys.exit(1)


@cli.group(cls=HubbleGroup)
def sat() -> None:
    """Receive satellite packets through a PlutoSDR."""


def _enable_sat_debug_logging(debug: bool) -> None:
    """Route the ``hubblenetwork.sat`` logger to stderr at DEBUG when *debug* is set."""
    if debug:
        sat_logger = logging.getLogger("hubblenetwork.sat")
        sat_logger.setLevel(logging.DEBUG)
        sat_logger.addHandler(_handler)


def _run_sat_scan(
    *,
    mock: bool,
    timeout: int | None,
    count: int | None,
    output_format: str,
    poll_interval: float,
    payload_format: str,
    key: str | None = None,
    days: int = 2,
    pluto_uri: str | None = None,
    debug: bool = False,
    counter_mode: str = UNIX_TIME,
    auto_detect_ctr: bool = False,
    show_failed_decryption: bool = False,
) -> None:
    """Shared implementation for ``sat scan`` and ``sat mock-scan``."""
    mode_label = "mock satellite receiver" if mock else "satellite receiver"

    _enable_sat_debug_logging(debug)

    is_tabular = output_format.lower() == "tabular"
    printer_class = _SAT_STREAMING_PRINTERS.get(
        output_format.lower(), _SatStreamingTablePrinter
    )
    printer = printer_class(
        payload_format=_effective_payload_format(
            click.get_current_context(), payload_format, is_tabular
        ),
        show_decrypt_status=show_failed_decryption,
        **({"show_debug_cols": debug} if is_tabular else {}),
    )

    # Pre-decode the key if provided.
    decoded_key: bytes | None = None
    if key:
        try:
            decoded_key = _parse_key(key)
        except ValueError as e:
            if printer.suppress_info_messages:
                click.echo(json.dumps({"error": f"Invalid key: {e}"}))
                return
            raise click.ClickException(f"Invalid key: {e}")

    if decoded_key is not None and auto_detect_ctr:
        _announce_auto_detect(
            auto_ctr=True, auto_eax=False, suppress=printer.suppress_info_messages
        )

    ctr_detector = CtrCounterModeDetector(
        auto_detect=auto_detect_ctr,
        fixed_counter_mode=counter_mode,
        days=days,
        key_len=len(decoded_key) if decoded_key is not None else 0,
    )

    # Fail fast: verify Docker is available before printing anything.
    try:
        sat_mod.ensure_docker_available()
    except sat_mod.DockerError as exc:
        _report_sat_error(exc, suppress_info_messages=printer.suppress_info_messages)

    if not printer.suppress_info_messages:
        click.echo(
            f"\nStarting {mode_label}  " + click.style("Ctrl+C to stop", dim=True),
            err=True,
        )
        click.secho(f"Web GUI  {sat_mod.web_ui_url()}", fg="cyan", err=True)

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
    hidden_failures = 0
    decrypt_ok = 0
    decrypt_fail = 0
    rssis: list[float] = []
    started = time.monotonic()
    try:
        for pkt in sat_mod.scan(
            timeout=timeout, poll_interval=poll_interval, mock=mock,
            pluto_uri=pluto_uri, on_status=_on_status,
        ):
            if decoded_key is not None:
                # With a key, the user wants only packets the key can decrypt.
                decrypted = None
                if pkt.auth_tag is not None:
                    # Satellite streams have no per-packet EID; omitting cache_key
                    # lets the detector share one per-stream slot for the scan.
                    d = ctr_detector.decrypt(
                        decrypt_fn=lambda pkt=pkt, **kw: decrypt_satellite(
                            decoded_key,
                            seq_no=pkt.seq_num,
                            auth_tag=pkt.auth_tag,
                            encrypted_payload=pkt.payload,
                            timestamp=pkt.timestamp,
                            **kw,
                        ),
                    )
                    _announce_detection(
                        d.label, suppress=printer.suppress_info_messages
                    )
                    decrypted = d.result
                if decrypted is not None:
                    decrypt_ok += 1
                    rssis.append(pkt.rssi_dB)
                    printer.print_row(
                        replace(pkt, payload=decrypted), decrypt_status="ok"
                    )
                elif show_failed_decryption:
                    decrypt_fail += 1
                    rssis.append(pkt.rssi_dB)
                    printer.print_row(pkt, decrypt_status="fail")
                else:
                    hidden_failures += 1
            else:
                rssis.append(pkt.rssi_dB)
                printer.print_row(pkt)
            if count is not None and printer.packet_count >= count:
                break
    except (sat_mod.DockerError, sat_mod.SatelliteError) as exc:
        error_occurred = True
        _report_sat_error(exc, suppress_info_messages=printer.suppress_info_messages)
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, old_handler)
        printer.finalize()

        if not printer.suppress_info_messages and not error_occurred:
            extra = None
            if rssis:
                extra = f"RSSI {max(rssis):.1f} to {min(rssis):.1f} dB"
            _scan_summary(
                printer.packet_count,
                time.monotonic() - started,
                hidden=hidden_failures,
                decrypted=decrypt_ok,
                failed=decrypt_fail,
                extra=extra,
                empty_hint=[
                    "The receiver ran but decoded nothing.",
                    "Check the antenna is connected and the device is transmitting,",
                    f"then watch the live view:  {sat_mod.web_ui_url()}",
                ],
            )


def _run_sat_one_shot(
    mode: str,
    duration: float,
    *,
    output_path: str | None,
    mock: bool,
    pluto_uri: str | None,
    debug: bool,
) -> None:
    """Shared implementation for the one-shot ``sat record`` / ``sat signal-report`` commands.

    Unlike ``scan``, these start the receiver, make a single blocking request
    for *duration* seconds, and write the result to a file. *mode* selects the
    entry in ``_ONE_SHOT_MODES`` and the ``sat_mod`` function to call.
    """
    _enable_sat_debug_logging(debug)

    try:
        sat_mod.ensure_docker_available()
    except sat_mod.DockerError as exc:
        _report_sat_error(exc)

    click.secho(f"[INFO] Web GUI: {sat_mod.web_ui_url()}", fg="green")

    def _on_status(msg: str) -> None:
        click.secho(f"[INFO] {msg}", fg="cyan", err=True)

    cfg = _ONE_SHOT_MODES[mode]
    out_path = output_path or cfg["default_name"]()

    click.secho(f"[INFO] {cfg['label']} for {duration}s... (Press Ctrl+C to stop)")
    try:
        result = getattr(sat_mod, mode)(
            duration,
            mock=mock,
            pluto_uri=pluto_uri,
            on_status=_on_status,
        )
    except (sat_mod.DockerError, sat_mod.SatelliteError) as exc:
        _report_sat_error(exc)
    except KeyboardInterrupt:
        click.secho("\n[INFO] Cancelled.", fg="yellow", err=True)
        sys.exit(130)

    with open(out_path, cfg["write_mode"]) as f:
        f.write(result)
    click.secho(f"[SUCCESS] Saved to {out_path}", fg="green")


# Shared by both sat option helpers below; kept in one place so the flag
# names/help stay in sync across ``sat scan`` and ``sat record``/``signal-report``.
def _sat_pluto_debug_options():
    return [
        click.option("--pluto-uri", "pluto_uri", type=str, default=None,
                     help="PlutoSDR URI passed to the container (e.g. usb:, ip:192.168.2.1)"),
        click.option("--debug", is_flag=True, default=False,
                     help="Enable debug logging to stderr"),
    ]


def _sat_one_shot_options(fn):
    """Apply the common sat record/signal-report Click options."""
    for decorator in reversed([
        click.option("--output", "output_path", type=click.Path(), default=None,
                     show_default=False,
                     help="Output file path (default: auto-generated name)"),
        click.option("--mock", is_flag=True, default=False,
                     help="Use the mock receiver -- no PlutoSDR hardware required"),
        *_sat_pluto_debug_options(),
    ]):
        fn = decorator(fn)
    return fn


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
                     type=click.Choice(["auto", "base64", "hex", "string"],
                                       case_sensitive=False),
                     default="base64", show_default=True,
                     help="Encoding format for packet payload. Tabular output "
                          "defaults to 'auto' (printable ASCII as text, otherwise "
                          "hex); JSON always defaults to base64."),
        *_sat_pluto_debug_options(),
    ]):
        fn = decorator(fn)
    return fn


@sat.command("scan", short_help="Stream satellite packets from a PlutoSDR")
@_sat_scan_options
@click.option(
    "--key",
    "-k",
    type=str,
    default=None,
    show_default=False,
    help="Key to decrypt packet payloads (hex or base64, 16 or 32 bytes). "
         "The counter source (UNIX_TIME / DEVICE_UPTIME) is auto-detected "
         "unless --counter-mode is given.",
)
@click.option(
    "--days",
    "-d",
    type=int,
    default=2,
    show_default=True,
    help="Days to search around each packet's timestamp when decrypting "
         "with the UNIX_TIME counter",
)
@click.option(
    "--counter-mode",
    type=click.Choice([UNIX_TIME, DEVICE_UPTIME], case_sensitive=False),
    default=UNIX_TIME,
    show_default=False,
    help="EID counter source for decryption. Omit to auto-detect from packets.",
)
@click.option(
    "--show-failed-decryption",
    is_flag=True,
    default=False,
    help="Show packets that fail decryption/authentication with the provided "
         "key. Adds a DECRYPT column indicating OK/FAIL.",
)
@click.pass_context
def sat_scan(ctx, **kwargs) -> None:
    """
    Start the satellite receiver and stream decoded packets.

    Requires Docker and a PlutoSDR device connected via USB.

    Pass --key to decrypt packet payloads locally; packets the key cannot
    decrypt are hidden unless --show-failed-decryption is given. The counter
    source is auto-detected (UNIX_TIME or DEVICE_UPTIME) unless --counter-mode
    is given explicitly.

    To capture raw IQ samples or an RF signal-diagnostic report to a file
    instead of streaming, use ``sat record`` or ``sat signal-report``.

    \b
    Example:
      hubblenetwork sat scan --timeout 30
      hubblenetwork sat scan -o json --timeout 10
      hubblenetwork sat scan -n 5
      hubblenetwork sat scan --key "a562a2f7e4c62bed52ab09633878f62b" --timeout 60
      hubblenetwork sat scan --debug           # Add RS_CORR/SYM_MS/GAP_MS columns
    """
    key = kwargs.get("key")
    counter_mode = kwargs["counter_mode"]

    def _explicit(name: str) -> bool:
        return ctx.get_parameter_source(name) == click.core.ParameterSource.COMMANDLINE

    # counter_mode defaults to UNIX_TIME, so a DEVICE_UPTIME value here always
    # means the user passed it explicitly (matches the ble scan/detect guards).
    if counter_mode == DEVICE_UPTIME:
        if not key:
            raise click.UsageError("--counter-mode DEVICE_UPTIME requires --key")
        if _explicit("days"):
            raise click.UsageError(
                "--counter-mode DEVICE_UPTIME and --days are mutually exclusive"
            )

    kwargs["auto_detect_ctr"] = key is not None and not _explicit("counter_mode")
    _run_sat_scan(mock=False, **kwargs)


@sat.command("mock-scan", short_help="Stream fake packets, no hardware needed")
@_sat_scan_options
def sat_mock_scan(**kwargs) -> None:
    """
    Start the satellite receiver in mock mode and stream synthetic packets.

    Uses simulated data -- no PlutoSDR hardware required. Useful for testing
    the satellite scanning interface.

    To capture simulated IQ samples or an RF signal-diagnostic report to a file
    instead of streaming, use ``sat record --mock`` or ``sat signal-report --mock``.

    Example:
      hubblenetwork sat mock-scan --timeout 30
      hubblenetwork sat mock-scan -o json -n 5
    """
    _run_sat_scan(mock=True, **kwargs)


@sat.command("record", short_help="Record raw IQ samples to a .npy file")
@click.argument(
    "duration", type=float, metavar="<seconds>",
    cls=GuidedArgument,
    guidance="  How many seconds of radio to capture. For example:\n    " + click.style("hubblenetwork sat record 10", fg="cyan"),
)
@_sat_one_shot_options
def sat_record(duration, output_path, mock, pluto_uri, debug) -> None:
    """
    Capture DURATION seconds of raw IQ samples and save them to a .npy file.

    Requires Docker. Records the raw radio signal without decoding it, for
    offline analysis or reprocessing. Pass --mock to use the simulated
    receiver instead of a PlutoSDR.

    Example:
      hubblenetwork sat record 10
      hubblenetwork sat record 10 --output capture.npy
      hubblenetwork sat record 10 --mock
    """
    _run_sat_one_shot(
        "record", duration, output_path=output_path, mock=mock,
        pluto_uri=pluto_uri, debug=debug,
    )


@sat.command("signal-report", short_help="Record IQ, write an RF diagnostic report")
@click.argument(
    "duration", type=float, metavar="<seconds>",
    cls=GuidedArgument,
    guidance="  How many seconds of radio to capture. For example:\n    " + click.style("hubblenetwork sat signal-report 10", fg="cyan"),
)
@_sat_one_shot_options
def sat_signal_report(duration, output_path, mock, pluto_uri, debug) -> None:
    """
    Record DURATION seconds and save an RF signal-diagnostic report to a text file.

    Requires Docker. Records raw IQ, then re-analyzes it offline into a
    plain-text report of per-symbol timing/drift, channel-hopping validation,
    amplitude/SNR, and chipset metrics -- a link-health diagnostic, not packet
    payloads. Pass --mock to use the simulated receiver instead of a PlutoSDR.

    Example:
      hubblenetwork sat signal-report 10
      hubblenetwork sat signal-report 10 --output report.txt
      hubblenetwork sat signal-report 10 --mock
    """
    _run_sat_one_shot(
        "signal_report", duration, output_path=output_path, mock=mock,
        pluto_uri=pluto_uri, debug=debug,
    )


def main(argv: list[str] | None = None) -> int:
    """
    Entry point used by console_scripts.

    Returns a process exit code instead of letting Click call sys.exit for easier testing.
    """
    try:
        # standalone_mode=False prevents Click from calling sys.exit itself.
        cli.main(args=argv, prog_name="hubblenetwork", standalone_mode=False)
    except SystemExit as e:
        return int(e.code)
    except click.UsageError as e:
        message = e.format_message()
        # A bare group raises a UsageError whose message is already the help
        # screen; printing a usage preamble and an "Error:" prefix on top of it
        # reads as a failure when it is really just "pick a subcommand".
        if message.startswith("Usage:"):
            click.echo("", err=True)
            click.echo(message, err=True)
            return e.exit_code
        if isinstance(e, click.NoSuchOption) and "Did you mean" not in message:
            names = []
            for param in (e.ctx.command.get_params(e.ctx) if e.ctx else []):
                if isinstance(param, click.Option):
                    names.extend(o for o in param.opts if o.startswith("--"))
            if names:
                message += "\n\n  This command accepts:\n    " + click.style(
                    "  ".join(sorted(names)), fg="cyan"
                )
        e.message = message
        # Keep Click's usage + "Try --help" preamble, then the red diagnosis and
        # any guidance lines below it.
        click.echo("", err=True)
        if e.ctx is not None:
            click.echo(e.ctx.get_usage(), err=True)
            # Prefer the long form: it self-documents when pasted into a script.
            names = e.ctx.help_option_names or ["--help"]
            hint = next((n for n in names if n.startswith("--")), names[0])
            click.echo(f"Try '{e.ctx.command_path} {hint}' for help.", err=True)
            click.echo("", err=True)
        head, _, rest = e.format_message().partition("\n")
        click.secho(f"Error: {head}", fg="red", bold=True, err=True)
        if rest:
            click.echo(rest, err=True)
        return e.exit_code
    except click.ClickException as e:
        message = e.format_message()
        click.echo("", err=True)
        if message.startswith("Usage:"):
            click.echo(message, err=True)
        else:
            # Only the first line is the diagnosis; guidance below it stays plain
            # so the suggested commands remain readable.
            head, _, rest = message.partition("\n")
            click.secho(f"Error: {head}", fg="red", bold=True, err=True)
            if rest:
                click.echo(rest, err=True)
        return e.exit_code
    except Exception as e:  # noqa: BLE001 - safety net to avoid tracebacks in user CLI
        click.secho(f"Unexpected error: {e}", fg="red", err=True)
        return 2
    return 0


if __name__ == "__main__":
    # Forward command-line args (excluding the program name) to main()
    raise SystemExit(main())
