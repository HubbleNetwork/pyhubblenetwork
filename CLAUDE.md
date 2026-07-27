# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pyhubblenetwork is a Python SDK for communicating with Hubble Network IoT devices over Bluetooth Low Energy (BLE) and securely relaying data to the Hubble Cloud. It provides both a programmatic API and a CLI tool.

## Commands

### Development Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

### Linting
```bash
ruff check src
```

### Running Tests
```bash
# Run all tests
pytest

# Run a single test file
pytest tests/test_cloud_integration.py

# Run a specific test class
pytest tests/test_cloud_integration.py::TestProdEnvironment

# Run a specific test
pytest tests/test_cloud_integration.py::TestProdEnvironment::test_list_devices

# Run integration tests (requires env vars)
pytest -m integration
```

### CLI Usage
```bash
hubblenetwork --help
hubblenetwork ble scan --timeout 10
hubblenetwork ble scan --network-id 4378792717 -o json
hubblenetwork ready scan
hubblenetwork org list-devices
hubblenetwork sat scan --timeout 30
hubblenetwork sat scan -o json -n 5
```

## Architecture

### Package Structure
The SDK uses a src layout with the main package at `src/hubblenetwork/`. Public API is exposed through `__init__.py` - import from the package top-level.

### Core Modules

- **`org.py`** - `Organization` class: credential-scoped operations (register devices, retrieve packets, list devices). Automatically resolves environment (PROD/TESTING) from credentials. `iter_devices()` and `iter_packets()` are generators that handle pagination without accumulating, each accepting an `on_page(page, total_so_far)` callback for progress; `list_devices()` and `retrieve_packets()` are `list()` wrappers over them and keep returning lists.

- **`cloud.py`** - Low-level HTTP client for Hubble Cloud API. Contains `Credentials`, `Environment` dataclasses and all REST endpoint functions. Uses `httpx` for HTTP requests.

- **`ble.py`** - BLE scanning for beacon packets (UUID 0xFCA6). Uses `bleak` library. Provides both sync (`scan()`) and async (`scan_async()`) variants. Automatically detects encrypted vs unencrypted protocol packets. Unencrypted protocol (version 1) packets carry a 34-bit network ID and up to 18 bytes of customer payload; `parse_unencrypted()` extracts these fields. AES-EAX protocol (version 2) packets carry a 2-byte nonce salt, 8-byte EID, encrypted payload (0-9 bytes), and 4-byte auth tag; `AesEaxPacket` stores these parsed fields. Unknown protocol versions (3+) are captured as `UnknownPacket`.

- **`ready.py`** - Hubble Ready device provisioning (UUID 0xFCA7). Handles GATT connections, characteristic reads/writes, and the full provisioning flow (register with backend, write key/config/time).

- **`crypto.py`** - Local packet decryption. Implements AES-CTR decryption with CMAC-based key derivation (SP800_108_Counter KDF). Supports both AES-256-CTR and AES-128-CTR. `decrypt()` accepts `counter_mode` as `"UNIX_TIME"` (default, UTC day-based) or `"DEVICE_UPTIME"` (counter-based, fixed pool size 128). Exports `UNIX_TIME` and `DEVICE_UPTIME` constants. `decrypt_eax()` decrypts AES-EAX packets by iterating counters 0-127, generating candidate EIDs via AES-ECB, and using `AES.MODE_EAX` for authenticated decryption. Uses key directly (no KDF). `decrypt_satellite()` decrypts a satellite packet's payload using the same AES-CTR/CMAC scheme as `decrypt()`; satellite packets deliver `seq_num`, `auth_tag`, and encrypted payload as separate fields (not packed into one advertisement). It accepts `counter_mode` (`"UNIX_TIME"` default, day-based; or `"DEVICE_UPTIME"`, sweeping the fixed 0-127 counter pool) just like `decrypt()`.

- **`detect.py`** - Decryption-strategy auto-detection, decoupled from the CLI (imports no `click`, never prints). `detect_eid_type()` classifies a key's EID rotation mode (UNIX_TIME / DEVICE_UPTIME / AMBIGUOUS) from sample packets. `CtrCounterModeDetector` and `EaxExponentDetector` are per-scan stateful objects that hold the detection cache and own the detect/sweep loop; their `decrypt()` takes a caller-supplied packet-bound `decrypt_fn` and returns a `Detection(result, label)` — `label` is set only on the first successful detection of a scan. The CLI builds the `decrypt_fn` (so test mocks of `cli.decrypt`/`cli.decrypt_eax` still apply) and prints the `[INFO] Detected:` line itself when `label` is set.

- **`packets.py`** - Data classes: `Location`, `EncryptedPacket`, `DecryptedPacket`, `AesEaxPacket`, `UnknownPacket`.

- **`device.py`** - `Device` dataclass representing a registered device.

- **`errors.py`** - Exception hierarchy. Base `HubbleError` with specialized errors for backend, network, validation, BLE scanning, and decryption failures.

- **`cli.py`** - Click-based CLI. Command groups: `ble` (scan, detect, check-time, validate), `ready` (scan, info, read-status, read-key-info, read-config, read-time, write-key, write-config, write-time, provision), `org` (info, list-devices, get-packets, register-device, delete-device, set-device-name), `sat` (scan, mock-scan, record, signal-report; `scan` accepts `--key`/`--days`/`--counter-mode`/`--show-failed-decryption` to decrypt payloads locally — when `--key` is given without `--counter-mode`, the counter source is auto-detected (UNIX_TIME vs DEVICE_UPTIME) and announced, mirroring `ble scan`. `record DURATION` captures raw IQ samples to a `.npy` file (container `/api/iq_capture`); `signal-report DURATION` records IQ then re-analyzes it offline into a plain-text RF signal-diagnostic report — per-symbol timing/drift, channel-hopping validation, amplitude/SNR, chipset metrics; **no packet payloads** (container `/api/record_analyze`). Both take `--output`/`--mock`/`--pluto-uri`/`--debug` and are one-shot — they start the receiver, make a single blocking request, and exit. `scan` polls the live `/api/packets` feed instead). Top-level: `validate-credentials`.

- **Scan output contract (`ble scan`, `sat scan`)** - Tabular output is one line per packet: `TIME`, `RSSI` plus a 5-cell signal bar (`_signal_bar()`, bar length carries magnitude), `V`, `EID`/`NET_ID`, `CTR/SEQ`, `PAYLOAD`, with a `✓`/`✗` decrypt mark in the gutter under `--show-failed-decryption`. Forensic columns sit behind `--debug` (`EPOCH`, `TAG`, `SALT` for BLE; `RS_CORR`, `SYM_MS`, `GAP_MS` for satellite). Three rules hold: packet rows are the only thing on **stdout** and all chrome (scanning notice, detection lines, summary via `_scan_summary()`) goes to **stderr**; `-o json` is byte-stable, so the tabular-only `auto` payload default is resolved by `_effective_payload_format()` rather than by changing the Click default; and cells truncate through `_fit()`, which appends the real byte count (`+18B`) so a row never outgrows its rule. Tests in `tests/test_cli_scan_display.py` lock all of this.

- **Org output contract (`org info`, `org list-devices`, `org get-packets`)** - Same column system, streamed through `Organization.iter_devices()` / `iter_packets()` rather than buffered, so the first rows land in ~1.6s instead of after a 15s silent fetch. `_OrgTablePrinter` renders rows, `_FetchProgress` reports page-by-page progress on stderr once the wait passes ~1s, and `_org_heading()` / `_org_summary()` keep all chrome on stderr. `--limit` defaults to off and always declares how a run stopped. `-o json` and `-o csv` still buffer, so their bytes are unchanged; the tabular-only `auto` payload default goes through `_effective_payload_format()`. `pass_orgcfg` resolves a `_LazyOrg` inside the command body, so `org <sub> --help` no longer needs credentials. Tests in `tests/test_cli_org_display.py` lock all of this.

- **Help and error-recovery contract** - Every group uses `cls=HubbleGroup`, which (a) renders help as a table of real invocations built from the Click tree via `_walk_commands()` / `_invocation()`, so a new command cannot go undocumented, and (b) overrides `resolve_command` to search the *whole* tree on an unknown name — Click only checks siblings, so from the root it can't see that `list-devices` lives under `org`. Ordering and blurbs come from `_GROUP_ORDER` / `_GROUP_BLURB`; the four examples come from `_START_HERE`; `_HELP_COL = 35` keeps the widest row inside 80. Every command carries a plain-language `short_help=` (asserted present and ≤44 chars for all 26). Required arguments use `cls=GuidedArgument` with a `metavar` (`<id>`, `<seconds>`) and `guidance` naming how to find the value. `_credentials_error()` distinguishes not-set from rejected; `_get_env_or_fail()` names the export. `main()` handles `UsageError` separately so the usage preamble survives, a message that is already a usage block gets no `Error:` prefix, and an unrecognised option gets the command's accepted option list appended. `validate-credentials` exits 1 on failure (it used to exit 0, making failure undetectable in scripts). Tests in `tests/test_cli_help_and_errors.py` lock all of this.

- **`sat.py`** - Satellite packet scanning via PlutoSDR. Manages Docker container lifecycle (pull, start, stop) and polls the container's HTTP API for decoded packets. Requires Docker daemon running. Image: `ghcr.io/hubblenetwork/sdr-docker:latest`. For real (non-mock) scans, after the receiver API is up `scan()` calls `_wait_for_sdr()`, which polls the container's `/api/status` `sdr_connected` field and raises `SatelliteError("No PlutoSDR detected …")` if the SDR never connects within the grace period — so a missing/unplugged Pluto fails fast instead of silently yielding nothing. The check is skipped for older receiver images that don't report `sdr_connected`.

### Key Patterns

- **Sync/Async duality**: BLE and provisioning functions have both sync and async variants. Sync versions use `asyncio.run()` with fallback handling for existing event loops.

- **Environment auto-detection**: `get_env_from_credentials()` tries PROD then TESTING to determine which API the credentials are valid for.

- **Pagination**: Cloud API uses continuation tokens. `Organization.list_devices()` and `retrieve_packets()` handle pagination internally.

- **Encryption modes**: Devices support either AES-256-CTR (32-byte key) or AES-128-CTR (16-byte key). Mode is auto-detected from device during provisioning.

- **EID modes**: Two EID rotation modes — UNIX_TIME and DEVICE_UPTIME. Device-uptime mode uses a fixed pool size of 128. The `decrypt()` function's `counter_mode` parameter accepts `"UNIX_TIME"` (default) or `"DEVICE_UPTIME"`; CLI commands use `--counter-mode UNIX_TIME|DEVICE_UPTIME`. For AES-128-EAX device registration on DEVICE_UPTIME, the rotation period can be set via `period_seconds` (SDK) / `--period-seconds` (CLI) or `period_exponent` / `--period-exponent` (period = 2^n seconds; cloud accepts 10-15, default 15 ≈ 9h). The two are mutually exclusive.

- **Satellite scanning requires Docker**: `sat.scan()` pulls and runs a privileged Docker container. Docker daemon must be running. Raises `DockerError` (not `SatelliteError`) if Docker is unavailable. The `docker` Python package is a required (not optional) dependency.

### Environment Variables
- `HUBBLE_ORG_ID` - Organization ID
- `HUBBLE_API_TOKEN` - API token
- For integration tests: `HUBBLE_PROD_ORG_ID`, `HUBBLE_PROD_API_TOKEN`, `HUBBLE_TESTING_ORG_ID`, `HUBBLE_TESTING_API_TOKEN`

### Releasing
Use the `/release` skill to cut a release. It bumps the version in `pyproject.toml`, generates release notes from conventional commits into `release-notes.md`, commits, tags (`vX.Y.Z`), and pushes. The tag push triggers `.github/workflows/release.yml` which runs tests, builds, creates a GitHub Release, and publishes to PyPI via trusted publishing.

### Conventions
- **Commit messages**: Use conventional commits — `feat(scope):`, `fix(scope):`, `docs:`, `test(scope):`, `chore:`. The scope is typically the module name (cli, org, ble, ready, sat, crypto).

### Test Markers
- `@pytest.mark.integration` - Tests requiring real API credentials
- `@pytest.mark.ble` - Tests requiring BLE hardware
