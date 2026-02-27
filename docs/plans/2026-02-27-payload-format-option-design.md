# Payload Format Option Design

**Date:** 2026-02-27
**Status:** Approved

## Goal

Add a `--payload-format` option to all CLI commands that display BLE packet payloads, allowing users to choose between base64 (default), hex, and UTF-8 string output.

## Affected Commands

- `ble scan`
- `ble detect`
- `org get-packets`

## Option

```
--payload-format  [base64|hex|string]  Payload encoding format  [default: base64]
```

## Approach

Add a `_format_payload(payload, fmt)` helper function, thread `payload_format` through all output paths, and add `--payload-format` Click options to the three commands.

## Helper Function

```python
def _format_payload(payload, fmt: str) -> str:
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
    else:  # "base64" (default)
        return base64.b64encode(payload).decode("ascii")
```

## Changes Required

| Location | Change |
|---|---|
| `_format_payload(payload, fmt)` | New helper |
| `_packet_to_dict(pkt, payload_format="base64")` | Add param, call helper |
| `_StreamingTablePrinter.__init__(payload_format="base64")` | Store fmt, use in `print_row` |
| `_StreamingJsonPrinter.__init__(payload_format="base64")` | Store fmt, pass to `_packet_to_dict` |
| `printer_class(payload_format=payload_format)` | Pass format when instantiating printers |
| `_print_packets_tabular(pkts, payload_format="base64")` | Add param, call helper (fixes pre-existing raw bytes bug) |
| `_print_packets_json(pkts, payload_format="base64")` | Add param, pass to `_packet_to_dict` |
| `_print_packets_csv(pkts, payload_format="base64")` | Add param, call helper |
| `_print_packets(pkts, output, payload_format)` | Thread through to batch functions |
| `ble scan`, `ble detect`, `org get-packets` | Add `--payload-format` Click option |

## Error Handling

- `string` mode with non-UTF-8 bytes: emit warning to stderr, display `<invalid UTF-8>`, continue scanning

## Pre-existing Bug Fixed

`_print_packets_tabular` (line 351) currently outputs raw `pkt.payload` bytes, not base64. This was missed in the previous session. The `payload_format` refactor corrects this.
