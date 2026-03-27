# Design: `ble validate` CLI Command

## Overview

Add a `ble validate` command that performs end-to-end validation of a Hubble device — inputs, credentials, device registration, BLE advertisement, encryption, and backend ingestion/retrieval. Mirrors the functionality of `hubble-device-sdk/tools/validate.py`.

## Command Interface

```
hubblenetwork ble validate --key <base64-key> --device-id <uuid> [--org-id <id>] [--token <token>] [--timeout <seconds>]
```

| Option | Short | Required | Default | Description |
|--------|-------|----------|---------|-------------|
| `--key` | `-k` | Yes | — | Device encryption key (base64-encoded) |
| `--device-id` | `-d` | Yes | — | Device UUID |
| `--org-id` | — | No | `HUBBLE_ORG_ID` env var | Organization ID |
| `--token` | — | No | `HUBBLE_API_TOKEN` env var | API token |
| `--timeout` | `-t` | No | 30 | BLE scan timeout in seconds |

Note: `--timeout` gets `-t` for consistency with `ble scan` and `ble detect`. `--org-id` and `--token` have no short flags to avoid conflicts with existing `ble` group conventions.

## Validation Steps

Seven sequential steps, each printing `[INFO]` then `[SUCCESS]` or `[ERROR]`:

1. **Validate inputs** — Decode base64 key, parse device-id as UUID. On failure, print formatting examples and exit.
2. **Get credentials** — Resolve org-id/token from CLI options or env vars via `_get_org_and_token()`.
3. **Validate org credentials** — Instantiate `Organization(org_id, api_token)`. Catch `InvalidCredentialsError`.
4. **Validate device registration** — Call `org.retrieve_packets(device)`. Catch `RequestError` (imported from `hubblenetwork.errors`) for unknown device ID.
5. **BLE scan** — Call `ble.scan(timeout=timeout)`. If no packets found, print troubleshooting tips and exit.
6. **Validate encryption** — Initialize `decrypted_pkt = None` and `pkt_to_ingest = None` before loop. Iterate scanned packets, call `decrypt(key, pkt)` on each. On first successful decryption, save both the `EncryptedPacket` (for ingest) and `DecryptedPacket` result, then break. If none decrypt, print key/provisioning debug tips and exit.
7. **Ingest + backend retrieval** — Wrap `org.ingest_packet(pkt_to_ingest)` in try/except (the `EncryptedPacket`, not decrypted); on failure print "not your fault" error matching source. Then poll `org.retrieve_packets(device, days=1)` up to 10 times (1s sleep between) looking for matching timestamp. If not found, exit with error.

On success, print `[COMPLETE] All validation steps passed!` and packet metadata (name, payload, sequence).

## Output Style

Matches the source script's colored step-by-step format:
- `[INFO]` — cyan, bold, followed by step description and `...`
- `[SUCCESS]` — green, bold, on same line after info
- `[ERROR]` — red, bold, followed by detailed error message with troubleshooting tips
- `[COMPLETE]` — green, bold, final summary

## Implementation

### Location

Single new command function `ble_validate()` in `cli.py`, registered under the existing `ble` group.

### Helper Functions

Three module-level helpers (prefixed `_validate_` for clarity):

- `_validate_info(msg)` — print `[INFO] msg...` in cyan
- `_validate_success()` — print `[SUCCESS]` in green
- `_validate_error(msg)` — print `[ERROR]` in red, print detailed message, call `sys.exit(1)`

One additional helper:
- `_get_pkt_from_be_with_timestamp(org, device, timestamp)` — search retrieved packets for matching timestamp

### Reused Existing Code

- `_get_org_and_token(org_id, token)` — credential resolution from options/env vars
- `Organization`, `Device`, `ble.scan()`, `decrypt()` — SDK primitives
- `InvalidCredentialsError` (from `hubblenetwork`), `RequestError` (from `hubblenetwork.errors`) — error types

### Error Messages

Error messages match the source script verbatim, including multi-line troubleshooting tips for BLE scanning failures, decryption failures, and input formatting issues.
