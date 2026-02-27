# Payload Format Option Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `--payload-format [base64|hex|string]` CLI option (default `base64`) to `ble scan`, `ble detect`, and `org get-packets` commands so users can control how packet payloads are displayed.

**Architecture:** Add a `_format_payload(payload, fmt)` helper, thread `payload_format` through `_packet_to_dict`, the streaming printer classes, and the batch `_print_packets_*` functions, then wire the new Click option to each of the three commands.

**Tech Stack:** Python, Click, `base64` stdlib module

---

## Context

### Files to touch
- **Modify:** `src/hubblenetwork/cli.py`
- **Modify:** `tests/test_cli_payload.py`

### Key locations in cli.py
- Line 31: good place to add `_format_payload` helper (after imports, before `_get_env_or_fail`)
- Line 50: `_packet_to_dict(pkt)` — add `payload_format="base64"` param
- Line 200: `_StreamingTablePrinter.__init__` — add `payload_format` param
- Line 263: `_StreamingTablePrinter.print_row` payload block
- Line 277: `_StreamingJsonPrinter.__init__` — add `payload_format` param
- Line 290: `_StreamingJsonPrinter.print_row` — pass fmt to `_packet_to_dict`
- Line 319: `_print_packets_tabular` — add `payload_format` param; fix pre-existing bug (line 351 uses raw `pkt.payload`)
- Line 358: `_print_packets_csv` — add `payload_format` param
- Line 371: `_print_packets_json` — add `payload_format` param
- Line 384: `_print_packets` — add `payload_format` param, thread through
- Line 463: `ble detect` command — add option + show actual payload
- Line 626: `ble scan` command — add option + pass to printer
- Line 708: `printer_class()` — becomes `printer_class(payload_format=payload_format)`
- Line 2256: `org get-packets` — add option + pass to `_print_packets`

---

## Task 1: Add `_format_payload` helper with tests

**Files:**
- Modify: `tests/test_cli_payload.py`
- Modify: `src/hubblenetwork/cli.py` (after line 30)

### Step 1: Write failing tests

Add this class to `tests/test_cli_payload.py` (after the existing imports/helpers, before `TestPacketToDict`):

```python
class TestFormatPayload:
    """Tests for the _format_payload helper."""

    def test_base64_encoding(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'\x01\x02\x03', "base64") == "AQID"

    def test_hex_encoding_uppercase(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'\xab\xc6\x79', "hex") == "ABC679"

    def test_hex_encoding_all_zeros(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'\x00\x00', "hex") == "0000"

    def test_string_encoding_valid_utf8(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'hello world', "string") == "hello world"

    def test_string_encoding_invalid_utf8_returns_fallback(self, capsys):
        from hubblenetwork.cli import _format_payload
        result = _format_payload(b'\xff\xfe', "string")
        assert result == "<invalid UTF-8>"

    def test_string_encoding_invalid_utf8_warns_to_stderr(self, capsys):
        from hubblenetwork.cli import _format_payload
        _format_payload(b'\xff\xfe', "string")
        captured = capsys.readouterr()
        assert "Warning" in captured.err

    def test_empty_bytes_base64(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'', "base64") == ""

    def test_empty_bytes_hex(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload(b'', "hex") == ""

    def test_non_bytes_passthrough(self):
        from hubblenetwork.cli import _format_payload
        assert _format_payload("already a string", "base64") == "already a string"
```

### Step 2: Run tests to verify they fail

```bash
pytest tests/test_cli_payload.py::TestFormatPayload -v
```

Expected: All FAIL with `ImportError: cannot import name '_format_payload'`

### Step 3: Add `_format_payload` to cli.py

Insert after line 30 (before `def _get_env_or_fail`):

```python
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

```

### Step 4: Run tests to verify they pass

```bash
pytest tests/test_cli_payload.py::TestFormatPayload -v
```

Expected: All 9 PASS

### Step 5: Commit

```bash
git add tests/test_cli_payload.py src/hubblenetwork/cli.py
git commit -m "feat(cli): add _format_payload helper for payload encoding"
```

---

## Task 2: Update `_packet_to_dict` to accept `payload_format`

**Files:**
- Modify: `tests/test_cli_payload.py`
- Modify: `src/hubblenetwork/cli.py:50-76`

### Step 1: Write new tests for non-default formats

Add to `TestPacketToDict` in `tests/test_cli_payload.py`:

```python
    def test_encrypted_packet_payload_hex(self):
        from hubblenetwork.cli import _packet_to_dict
        raw = b'\xab\xc6\x79'
        pkt = make_encrypted_packet(raw)
        result = _packet_to_dict(pkt, payload_format="hex")
        assert result["payload"] == "ABC679"

    def test_decrypted_packet_payload_string(self):
        from hubblenetwork.cli import _packet_to_dict
        raw = b'sensor:42'
        pkt = make_decrypted_packet(raw)
        result = _packet_to_dict(pkt, payload_format="string")
        assert result["payload"] == "sensor:42"

    def test_decrypted_packet_payload_string_invalid_utf8(self, capsys):
        from hubblenetwork.cli import _packet_to_dict
        raw = b'\xff\xfe'
        pkt = make_decrypted_packet(raw)
        result = _packet_to_dict(pkt, payload_format="string")
        assert result["payload"] == "<invalid UTF-8>"
        captured = capsys.readouterr()
        assert "Warning" in captured.err
```

### Step 2: Run to verify they fail

```bash
pytest tests/test_cli_payload.py::TestPacketToDict::test_encrypted_packet_payload_hex -v
```

Expected: FAIL (function doesn't accept `payload_format` param yet)

### Step 3: Update `_packet_to_dict` signature and body

Replace the current `_packet_to_dict` function (lines 50-76):

```python
def _packet_to_dict(pkt, payload_format: str = "base64") -> dict:
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

    data["payload"] = _format_payload(pkt.payload, payload_format)

    if not pkt.location.fake:
        data["location"] = {
            "lat": pkt.location.lat,
            "lon": pkt.location.lon,
        }

    return data
```

### Step 4: Run all `TestPacketToDict` tests

```bash
pytest tests/test_cli_payload.py::TestPacketToDict -v
```

Expected: All 7 PASS (3 original + 3 new, plus the empty payload test)

### Step 5: Commit

```bash
git add tests/test_cli_payload.py src/hubblenetwork/cli.py
git commit -m "feat(cli): add payload_format param to _packet_to_dict"
```

---

## Task 3: Update streaming printers to accept `payload_format`

**Files:**
- Modify: `tests/test_cli_payload.py`
- Modify: `src/hubblenetwork/cli.py` (classes `_StreamingTablePrinter` and `_StreamingJsonPrinter`)

### Step 1: Write failing tests

Add to `tests/test_cli_payload.py`:

```python
class TestStreamingTablePrinterPayloadFormat:
    """Tests for _StreamingTablePrinter with non-default payload formats."""

    def test_hex_format(self, capsys):
        from hubblenetwork.cli import _StreamingTablePrinter
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingTablePrinter(payload_format="hex")
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_string_format_valid_utf8(self, capsys):
        from hubblenetwork.cli import _StreamingTablePrinter
        raw = b'sensor:42'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingTablePrinter(payload_format="string")
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert "sensor:42" in captured.out

    def test_default_is_still_base64(self, capsys):
        from hubblenetwork.cli import _StreamingTablePrinter
        raw = b'\x01\x02\x03'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingTablePrinter()
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert base64.b64encode(raw).decode("ascii") in captured.out


class TestStreamingJsonPrinterPayloadFormat:
    """Tests for _StreamingJsonPrinter with non-default payload formats."""

    def test_hex_format(self, capsys):
        from hubblenetwork.cli import _StreamingJsonPrinter
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingJsonPrinter(payload_format="hex")
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_default_is_base64(self, capsys):
        from hubblenetwork.cli import _StreamingJsonPrinter
        raw = b'\x01\x02\x03'
        pkt = make_decrypted_packet(raw)
        printer = _StreamingJsonPrinter()
        printer.print_row(pkt)
        captured = capsys.readouterr()
        assert base64.b64encode(raw).decode("ascii") in captured.out
```

### Step 2: Run to verify they fail

```bash
pytest tests/test_cli_payload.py::TestStreamingTablePrinterPayloadFormat tests/test_cli_payload.py::TestStreamingJsonPrinterPayloadFormat -v
```

Expected: FAIL (`__init__() got an unexpected keyword argument 'payload_format'`)

### Step 3: Update `_StreamingTablePrinter`

Change `__init__` (around line 200) from:
```python
    def __init__(self):
        super().__init__()
        self._header_printed = False
        self._headers: List[str] = []
        self._column_config: dict = {}
```

To:
```python
    def __init__(self, payload_format: str = "base64"):
        super().__init__()
        self._header_printed = False
        self._headers: List[str] = []
        self._column_config: dict = {}
        self._payload_format = payload_format
```

Change the payload block in `print_row` (around line 262) from:
```python
        if self._column_config["is_decrypted"]:
            payload = pkt.payload
            b64 = (
                base64.b64encode(payload).decode("ascii")
                if isinstance(payload, bytes)
                else str(payload)
            )
            row.append(b64)
```

To:
```python
        if self._column_config["is_decrypted"]:
            row.append(_format_payload(pkt.payload, self._payload_format))
```

### Step 4: Update `_StreamingJsonPrinter`

Change `__init__` (around line 278) from:
```python
    def __init__(self):
        super().__init__()
        self._array_started = False
```

To:
```python
    def __init__(self, payload_format: str = "base64"):
        super().__init__()
        self._array_started = False
        self._payload_format = payload_format
```

Change `print_row` (around line 290) from:
```python
        pkt_dict = _packet_to_dict(pkt)
```

To:
```python
        pkt_dict = _packet_to_dict(pkt, self._payload_format)
```

### Step 5: Run all streaming printer tests

```bash
pytest tests/test_cli_payload.py::TestStreamingTablePrinter tests/test_cli_payload.py::TestStreamingTablePrinterPayloadFormat tests/test_cli_payload.py::TestStreamingJsonPrinterPayloadFormat -v
```

Expected: All PASS

### Step 6: Commit

```bash
git add tests/test_cli_payload.py src/hubblenetwork/cli.py
git commit -m "feat(cli): add payload_format to streaming printers"
```

---

## Task 4: Update batch printer functions

**Files:**
- Modify: `tests/test_cli_payload.py`
- Modify: `src/hubblenetwork/cli.py` (`_print_packets_tabular`, `_print_packets_csv`, `_print_packets_json`, `_print_packets`)

### Step 1: Write failing tests

Add to `tests/test_cli_payload.py`:

```python
class TestBatchPrinters:
    """Tests for _print_packets_* functions with payload_format."""

    def test_tabular_hex(self, capsys):
        from hubblenetwork.cli import _print_packets_tabular
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        _print_packets_tabular([pkt], payload_format="hex")
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_tabular_default_base64(self, capsys):
        from hubblenetwork.cli import _print_packets_tabular
        raw = b'\x01\x02\x03'
        pkt = make_decrypted_packet(raw)
        _print_packets_tabular([pkt])
        captured = capsys.readouterr()
        assert base64.b64encode(raw).decode("ascii") in captured.out

    def test_json_hex(self, capsys):
        from hubblenetwork.cli import _print_packets_json
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        _print_packets_json([pkt], payload_format="hex")
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_csv_hex(self, capsys):
        from hubblenetwork.cli import _print_packets_csv
        raw = b'\xab\xc6\x79'
        pkt = make_decrypted_packet(raw)
        _print_packets_csv([pkt], payload_format="hex")
        captured = capsys.readouterr()
        assert "ABC679" in captured.out

    def test_csv_string(self, capsys):
        from hubblenetwork.cli import _print_packets_csv
        raw = b'temp:25'
        pkt = make_decrypted_packet(raw)
        _print_packets_csv([pkt], payload_format="string")
        captured = capsys.readouterr()
        assert "temp:25" in captured.out
```

### Step 2: Run to verify they fail

```bash
pytest tests/test_cli_payload.py::TestBatchPrinters -v
```

Expected: FAIL (functions don't accept `payload_format` yet)

### Step 3: Update `_print_packets_tabular`

Replace the current function (around lines 319-355). The key change is adding the `payload_format` param and replacing the raw `pkt.payload` bug on line 351:

```python
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
```

### Step 4: Update `_print_packets_csv`

Replace the current function (around lines 358-368):

```python
def _print_packets_csv(pkts, payload_format: str = "base64") -> None:
    click.echo("timestamp, datetime, latitude, longitude, payload")
    for pkt in pkts:
        ts = datetime.fromtimestamp(pkt.timestamp).strftime("%c")
        payload_str = _format_payload(pkt.payload, payload_format)
        click.echo(
            f'{pkt.timestamp}, {ts}, {pkt.location.lat:.6f}, {pkt.location.lon:.6f}, "{payload_str}"'
        )
```

### Step 5: Update `_print_packets_json`

Replace (around lines 371-374):

```python
def _print_packets_json(pkts, payload_format: str = "base64") -> None:
    """Print packets as a JSON array."""
    json_packets = [_packet_to_dict(pkt, payload_format) for pkt in pkts]
    click.echo(json.dumps(json_packets, indent=2))
```

### Step 6: Update `_print_packets`

Replace (around lines 384-394). The `globals()` dispatch can't easily pass keyword args, so convert to explicit calls:

```python
def _print_packets(pkts, output: str = "tabular", payload_format: str = "base64") -> None:
    format_key = (output or "tabular").lower().strip()
    if format_key == "json":
        _print_packets_json(pkts, payload_format)
    elif format_key == "csv":
        _print_packets_csv(pkts, payload_format)
    else:
        _print_packets_tabular(pkts, payload_format)
```

Note: You can also remove the `_OUTPUT_FORMATS` dict (lines 377-381) since it's no longer used.

### Step 7: Run all batch printer tests

```bash
pytest tests/test_cli_payload.py::TestBatchPrinters -v
```

Expected: All 5 PASS

### Step 8: Run full test suite

```bash
pytest
```

Expected: All pass (no regressions)

### Step 9: Commit

```bash
git add tests/test_cli_payload.py src/hubblenetwork/cli.py
git commit -m "feat(cli): add payload_format to batch printer functions"
```

---

## Task 5: Wire up `--payload-format` option to all three commands

**Files:**
- Modify: `src/hubblenetwork/cli.py` (`ble scan`, `ble detect`, `org get-packets`)

No new tests needed — the helper and printer tests already cover the logic. This task is pure wiring.

### Step 1: Update `ble scan`

Add the Click option decorator before `@click.pass_context` (around line 674). Add after the existing `--format` option block:

```python
@click.option(
    "--payload-format",
    "payload_format",
    type=click.Choice(["base64", "hex", "string"], case_sensitive=False),
    default="base64",
    show_default=True,
    help="Encoding format for packet payload",
)
```

Add `payload_format: str = "base64"` to the `ble_scan` function signature.

Change `printer = printer_class()` (line 708) to:
```python
printer = printer_class(payload_format=payload_format)
```

### Step 2: Update `ble detect`

Add the same Click option decorator before `@click.pass_context` for `ble detect` (around line 510).

Add `payload_format: str = "base64"` to the `ble_detect` function signature.

Change the success output block (around lines 600-615) to include the actual payload.

Current JSON output block:
```python
            if use_json:
                result = {
                    "success": True,
                    "packet": {
                        "datetime": datetime_str,
                        "rssi": decrypted_pkt.rssi,
                        "payload_bytes": len(decrypted_pkt.payload),
                        "counter": decrypted_pkt.counter,
                    },
                }
                click.echo(json.dumps(result))
            else:
                click.secho("[SUCCESS] ", fg="green", nl=False)
                click.echo(
                    f"Packet decrypted: {datetime_str}, RSSI: {decrypted_pkt.rssi} dBm, {len(decrypted_pkt.payload)} bytes, counter: {decrypted_pkt.counter}"
                )
```

Replace with:
```python
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
```

### Step 3: Update `org get-packets`

Add the Click option decorator (around line 2256):

```python
@click.option(
    "--payload-format",
    "payload_format",
    type=click.Choice(["base64", "hex", "string"], case_sensitive=False),
    default="base64",
    show_default=True,
    help="Encoding format for packet payload",
)
```

Add `payload_format: str = "base64"` to the `get_packets` function signature.

Change the call from:
```python
    _print_packets(packets, output_format)
```

To:
```python
    _print_packets(packets, output_format, payload_format)
```

### Step 4: Run full test suite

```bash
pytest
```

Expected: All pass

### Step 5: Verify help text

```bash
hubblenetwork ble scan --help
hubblenetwork ble detect --help
hubblenetwork org get-packets --help
```

Expected: Each shows `--payload-format [base64|hex|string]` option with default `base64`.

### Step 6: Commit

```bash
git add src/hubblenetwork/cli.py
git commit -m "feat(cli): add --payload-format option to ble scan, ble detect, org get-packets"
```

---

## Verification

After all tasks complete:

```bash
# Full test suite should pass
pytest

# Help text should show the new option
hubblenetwork ble scan --help | grep payload-format
hubblenetwork org get-packets --help | grep payload-format
```

The `ble scan` and `ble detect` commands require BLE hardware for end-to-end testing, but the unit tests cover the core logic.
