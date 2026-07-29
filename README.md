# pyhubblenetwork

[![PyPI](https://img.shields.io/pypi/v/pyhubblenetwork.svg)](https://pypi.org/project/pyhubblenetwork)
[![Python](https://img.shields.io/pypi/pyversions/pyhubblenetwork.svg)](https://pypi.org/project/pyhubblenetwork)
[![License](https://img.shields.io/github/license/HubbleNetwork/pyhubblenetwork)](LICENSE)

**pyhubblenetwork** is a Python SDK for communicating with Hubble Network devices over Bluetooth Low Energy (BLE) and securely relaying data to the Hubble Cloud. It provides a simple API for scanning, sending, and managing devices—no embedded firmware knowledge required.


## Table of contents

- [Quick links](#quick-links)
- [Requirements & supported platforms](#requirements--supported-platforms)
- [Installation](#installation)
- [Quick start](#quick-start)
- [CLI usage](#cli-usage)
- [Validating a device end-to-end](#validating-a-device-end-to-end)
- [Satellite scanning (PlutoSDR)](#satellite-scanning-plutosdr)
- [Configuration](#configuration)
- [Public API (summary)](#public-api-summary)
- [Development & tests](#development--tests)
- [Troubleshooting](#troubleshooting)
- [Telemetry](#telemetry)
- [Releases & versioning](#releases--versioning)


## Quick links

- [PyPI](https://pypi.org/project/pyhubblenetwork/): `pip install pyhubblenetwork`
- [Hubble official doc site](https://docs.hubble.com/docs/intro)
- [Hubble embedded SDK](https://github.com/HubbleNetwork/sdk)


## Requirements & supported platforms

- Python **3.10+** (3.11/3.12 recommended)
- BLE platform prerequisites (only needed if you use `ble.scan()`):
  - **macOS**: CoreBluetooth. Run from a real terminal app and grant it Bluetooth
    access when prompted. macOS kills any process whose executable has no
    `NSBluetoothAlwaysUsageDescription` in an Info.plist, and a bare Python binary
    has none — see [Troubleshooting](#troubleshooting) if you hit a crash rather
    than a permission prompt.
  - **Linux**: BlueZ required; user must have permission to access the BLE adapter (often `bluetooth` group).
  - **Windows**: Requires a compatible BLE stack/adapter.
- Satellite scanning prerequisites (only needed if you use `sat.scan()`):
  - **Docker**: [Docker Desktop](https://www.docker.com/get-started/) (macOS/Windows) or Docker Engine (Linux) must be installed and running.
  - **PlutoSDR**: An Analog Devices ADALM-PLUTO SDR dongle connected via USB.

## Installation

### Users (stable release)

```bash
pip install pyhubblenetwork
# or install CLI into an isolated environment:
pipx install pyhubblenetwork
```

### Developers (editable install)

From the repo root:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

## Quick start

### Scan locally, then ingest to backend

```python
from hubblenetwork import ble, Organization

org = Organization(org_id="org_123", api_token="sk_XXX")
pkts = ble.scan(timeout=5.0)
if len(pkts) > 0:
    org.ingest_packet(pkts[0])
else:
    print("No packet seen within timeout")
```

### Manage devices and query packets

```python
from hubblenetwork import Organization

org = Organization(org_id="org_123", api_token="sk_XXX")

# Create a new device
new_dev = org.register_device()
print("new device id:", new_dev.id)

# List devices
for d in org.list_devices():
    print(d.id, d.name)

# Get packets from a device (returns a list of DecryptedPacket)
packets = org.retrieve_packets(new_dev)
if len(packets) > 0:
    print("latest RSSI:", packets[0].rssi, "payload bytes:", len(packets[0].payload))
```

### Local decryption (when you have the key)

```python
from hubblenetwork import Device, ble, decrypt
from typing import Optional

dev = Device(id="dev_abc", key=b"<secret-key>")

pkts = ble.scan(timeout=5.0)  # might return a list or a single packet depending on API
for pkt in pkts:
    maybe_dec = decrypt(dev.key, pkt)
    if maybe_dec:
        print("payload:", maybe_dec.payload)
    else:
        print("failed to decrypt packet")
```

For devices using counter-based EID (DEVICE_UPTIME mode), pass `counter_mode="DEVICE_UPTIME"`:

```python
maybe_dec = decrypt(dev.key, pkt, counter_mode="DEVICE_UPTIME")
```

The `counter_mode` parameter accepts `"UNIX_TIME"` (default, UTC day-based) or `"DEVICE_UPTIME"` (counter values 0–127, fixed pool size of 128).

### Receive satellite packets

```python
from hubblenetwork import sat

# sat.scan() manages the Docker container automatically:
# pulls the image, starts the container, polls for packets, and stops on exit.
for pkt in sat.scan(timeout=60.0):
    print(f"device={pkt.device_id}  seq={pkt.seq_num}  rssi={pkt.rssi_dB} dB  payload={pkt.payload.hex()}")
```

Docker must be running before calling `sat.scan()`. The PlutoSDR dongle must be connected.

## CLI usage

If installed, the `hubblenetwork` command is available:

```bash
hubblenetwork --help
hubblenetwork ble scan
hubblenetwork ble scan --payload-format hex
hubblenetwork ble scan --key "base64key=" --counter-mode DEVICE_UPTIME  # counter-based EID
hubblenetwork org get-packets <id> --payload-format string
```

Start with `hubblenetwork doctor`, which checks whether this machine can actually
talk to Hubble and names the fix for anything broken:

```bash
hubblenetwork doctor
```

```
  x Credentials    not set
      Set both, or pass --org-id/--token:
        export HUBBLE_ORG_ID=<your org id>
        export HUBBLE_API_TOKEN=<your api token>
  + Bluetooth      usage description present
  x Docker         Docker is not available
      Only `sat` commands need Docker.

Not ready.  |  1 ok  |  2 failed
```

It exits 1 when something needed is broken, so a script can gate on it. A skipped
check is not a failure: it means the check does not apply on this platform, or could
not be answered without doing real work (pulling the satellite receiver image, say).
The Bluetooth check reads the interpreter's Info.plist rather than attempting a scan,
because attempting one is exactly what macOS kills.

Every command lives inside a group, so it is always `hubblenetwork <group> <command>`:
`org` for the cloud, `ble` for nearby devices, `ready` for provisioning, `sat` for
satellite, `metrics` for fleet counts. `hubblenetwork --help` prints the full list with
a one-line description and the required arguments for each, and every command takes
`--help` for its own options.

You don't have to remember which group a command is in. If you type one at the wrong
level the CLI finds it for you:

```
$ hubblenetwork list-devices

Usage: hubblenetwork [OPTIONS] COMMAND [ARGS]...
Try 'hubblenetwork --help' for help.

Error: No such command 'list-devices'.

  Did you mean:  hubblenetwork org list-devices
```

The same applies to missing arguments (they say how to find the value), unknown options
(they list what the command accepts), and missing credentials (they name the environment
variables and the flags). `validate-credentials` exits 1 when credentials are invalid, so
scripts can branch on it.

### Payload format option

Commands that output packet data (`ble scan`, `sat scan`, `ble detect`, `org get-packets`) support the `--payload-format` flag to control how payloads are displayed:

* `auto` — printable ASCII shows as text, anything else as uppercase hex
* `base64` — encode payloads as base64
* `hex` — display payloads as hexadecimal
* `string` — decode payloads as UTF-8 text (falls back to `<invalid UTF-8>` if bytes are not valid UTF-8)

All four values work with every output format, but the **default** differs by
format, because a person and a program want different things. Tabular output
defaults to `auto`, so a decrypted payload reads as `T=21.4` rather than
`VD0yMS40`. JSON and CSV default to `base64` so the machine contract stays
stable. An explicit `--payload-format` always wins.

### Organization commands

`org list-devices` and `org get-packets` stream rows as pages arrive, so the first
rows appear in about a second rather than after the whole window downloads. A busy
device can hold tens of thousands of packets; Ctrl+C stops early and still prints a
summary, and `--limit N` caps the run (it says how it stopped, never silently).

```bash
hubblenetwork org info
hubblenetwork org list-devices              # streams, tags summarised once
hubblenetwork org list-devices -f json      # machine-readable
hubblenetwork org list-devices -n 20
hubblenetwork org get-packets <id> -n 50 --debug
```

`list-devices` takes `--format tabular|json` and `--limit`. `get-packets` takes
`--limit` and `--debug` (which adds `EPOCH`, `CTR` and `SEQ` columns). As with the
scan commands, rows go to stdout and headings, progress and summaries go to stderr.

The SDK mirrors this: `Organization.iter_devices()` and `Organization.iter_packets()`
are generators that yield as pages arrive, and both accept an `on_page(page, total)`
callback for progress. `list_devices()` and `retrieve_packets()` still return lists.

### Scan output layout

`ble scan` and `sat scan` print one line per packet with a signal bar, and close
with a summary on stderr:

```
    TIME     RSSI       V EID              CTR/SEQ PAYLOAD
─────────────────────────────────────────────────────────────────────────────
✓   00:06:40  -62 ███▏  2 9c4e2ab77d3f0e1a   20320 T=21.4,B=87
✓   00:06:43  -66 ██▉   2 9c4e2ab77d3f0e1b   20321 T=21.4,B=87
✗   00:06:49  -74 ██▏   2 9c4e2ab77d3f0e1d       - D307912C66BA4018E5
─────────────────────────────────────────────────────────────────────────────

4 packets  ·  3 decrypted, 1 failed  ·  RSSI -62 to -74 dBm  ·  12s
```

The bar next to RSSI is signal strength: length is the magnitude, so you can watch
it shrink as you walk away from a device. The `✓`/`✗` mark only appears with
`--show-failed-decryption`, and the mark carries the state on its own, so the output
still reads correctly without colour.

### Terminals that can't do box-drawing

Not every terminal can render `─` and `█`. Writing them to a stdout using a legacy
code page raises `UnicodeEncodeError`, and because most of them are East Asian Width
"Ambiguous" they render double-width under a CJK terminal configuration, which shears
every column.

Pass `--ascii` (or set `HUBBLE_ASCII=1`) for a pure-ASCII rendering with identical
column widths:

```
  TIME     RSSI       V EID              CTR/SEQ PAYLOAD
---------------------------------------------------------------------------
  15:50:13  -62 ###=  0 2030405              300 0A0B0C0D0E0F
---------------------------------------------------------------------------

1 packets  |  RSSI -62 to -62 dBm  |  0s
```

The encoding case is detected automatically, so you only need the flag for the
double-width one. `--no-ascii` forces the Unicode rendering if the detection is
wrong for you.

Colour is a separate axis: `--no-color`, `NO_COLOR=1`, or a non-TTY stdout all
disable it, and `FORCE_COLOR=1` keeps it on where a pipe would otherwise strip it
(useful in CI). Both flags work on any command, before or after the subcommand.

Packet rows go to stdout and everything else (the scanning notice, detection
lines, the summary) goes to stderr, so `hubblenetwork ble scan > packets.txt`
captures data only. Pass `--debug` to add the forensic columns: `EPOCH`, `TAG`
and `SALT` for `ble scan`, `RS_CORR`, `SYM_MS` and `GAP_MS` for `sat scan`.

## Validating a device end-to-end

The `ble validate` command runs a full end-to-end health check on a single Hubble
device, confirming that everything from your credentials to the cloud backend is
wired up correctly. It is the quickest way to answer "is my device working?"

```bash
hubblenetwork ble validate \
  --key "a562a2f7e4c62bed52ab09633878f62b" \
  --device-id "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"
```

The command performs these steps in order, stopping at the first failure:

1. **Validates input formats** — the device key (hex or base64, 16- or 32-byte)
   and the device ID (standard 8-4-4-4-12 UUID).
2. **Loads credentials** — from `--org-id`/`--token` or the `HUBBLE_ORG_ID` and
   `HUBBLE_API_TOKEN` environment variables.
3. **Validates the organization credentials** against the backend.
4. **Confirms the device is registered** in your organization.
5. **Scans for BLE advertisements** from Hubble-compatible devices.
6. **Decrypts a received packet** with the provided key and reports the detected
   EID type (`UNIX_TIME` or `DEVICE_UPTIME`).
7. **Ingests the packet** into the backend and **reads it back** to confirm the
   full round trip succeeded.

### Options

| Option | Description |
|--------|-------------|
| `--key`, `-k` | Device key, used to test packet encryption (required). Accepts hex or base64, 16- or 32-byte. |
| `--device-id`, `-d` | Device UUID, used to test the backend (required). |
| `--org-id` | Organization ID (defaults to the `HUBBLE_ORG_ID` env var). |
| `--token` | API token (defaults to the `HUBBLE_API_TOKEN` env var). |
| `--timeout`, `-t` | BLE scan timeout in seconds (default: 30). |

If a step fails, the command prints targeted debugging tips. A common cause of a
failed scan is a slow advertising interval combined with OS-level BLE scan
optimizations — simply running the command again often resolves it.

## Satellite scanning (PlutoSDR)

The `sat` command group receives packets via a PlutoSDR SDR dongle. It runs a Docker container ([`ghcr.io/hubblenetwork/sdr-docker`](https://ghcr.io/hubblenetwork/sdr-docker)) that handles RF reception and decoding, then polls that container's HTTP API and streams decoded packets to stdout.

### Requirements

- **Docker daemon running** — Docker Desktop (macOS/Windows) or Docker Engine (Linux).
- **PlutoSDR connected** — ADALM-PLUTO dongle plugged in via USB before starting the scan.

### CLI commands

```bash
# Stream packets until Ctrl+C
hubblenetwork sat scan

# Stop after 30 seconds
hubblenetwork sat scan --timeout 30

# Stop after receiving 5 packets
hubblenetwork sat scan -n 5

# JSON output (a single array, streamed as packets arrive)
hubblenetwork sat scan -o json

# Combine options
hubblenetwork sat scan -o json --timeout 60 -n 20

# Decrypt payloads locally with a device key (hex or base64, 16 or 32 bytes)
hubblenetwork sat scan --key "a562a2f7e4c62bed52ab09633878f62b"

# Force the DEVICE_UPTIME counter instead of auto-detecting
hubblenetwork sat scan --key "<key>" --counter-mode DEVICE_UPTIME

# Show packets the key can't decrypt too (adds a ✓/✗ decrypt mark per row)
hubblenetwork sat scan --key "<key>" --show-failed-decryption
```

When `--key` is supplied, each packet's payload is decrypted locally using the
same AES-CTR scheme as BLE, which supports both the UNIX_TIME (day-based) and
DEVICE_UPTIME counter sources. The counter source is auto-detected from the
packets (and announced) unless `--counter-mode UNIX_TIME|DEVICE_UPTIME` is given.
For the UNIX_TIME counter, `--days` controls how many days around each packet's
timestamp are searched (default 2). Packets the key cannot decrypt are hidden
unless `--show-failed-decryption` is given.

The command automatically:
1. Verifies Docker is available
2. Pulls the latest PlutoSDR image (if not cached)
3. Starts the container in privileged mode so it can access USB
4. Waits for the receiver API to become ready
5. Streams new packets as they arrive (deduplicating by device ID + sequence number)
6. Stops and removes the container on exit or Ctrl+C

### One-shot capture (`record` / `signal-report`)

Alongside the live `scan` stream, two one-shot commands record for a fixed
duration, save a single file, and exit. Both accept `--output PATH` (default: an
auto-generated timestamped name), `--mock` (use the simulated receiver — no
PlutoSDR required), `--pluto-uri`, and `--debug`.

```bash
# Capture 10 s of raw IQ samples to a .npy file (for offline analysis / reprocessing)
hubblenetwork sat record 10
hubblenetwork sat record 10 --output capture.npy

# Record 10 s and save an RF signal-diagnostic report to a .txt file
hubblenetwork sat signal-report 10
hubblenetwork sat signal-report 10 --output report.txt --mock
```

- **`record`** captures the raw radio signal only — no decoding. The output is a
  NumPy `.npy` file of IQ samples.
- **`signal-report`** records IQ, then re-analyzes it offline into a plain-text
  **link-health diagnostic**: per-symbol timing/drift, channel-hopping
  validation, amplitude/SNR, and chipset metrics. It reports on signal quality
  and does **not** contain decoded packet payloads — to receive payloads, use
  `sat scan` (optionally with `--key`).

### Python API

```python
from hubblenetwork import sat, SatellitePacket

# Generator — yields SatellitePacket as packets arrive
for pkt in sat.scan(timeout=60.0, poll_interval=2.0):
    print(pkt.device_id, pkt.seq_num, pkt.rssi_dB, pkt.payload.hex())

# Or fetch the current packet buffer without managing the container yourself
packets: list[SatellitePacket] = sat.fetch_packets()

# One-shot captures (manage the container, run once, return the result)
iq_bytes: bytes = sat.record(10.0)          # raw IQ samples (.npy file body)
report: str = sat.signal_report(10.0)       # plain-text RF signal-diagnostic report

# Decrypt a packet's payload locally.
# counter_mode defaults to UNIX_TIME; pass DEVICE_UPTIME for uptime-based EIDs.
from hubblenetwork import decrypt_satellite

for pkt in sat.scan(timeout=60.0):
    if pkt.auth_tag is not None:
        plaintext = decrypt_satellite(
            key, seq_no=pkt.seq_num, auth_tag=pkt.auth_tag,
            encrypted_payload=pkt.payload, timestamp=pkt.timestamp,
            counter_mode="UNIX_TIME",
        )
        if plaintext is not None:
            print(pkt.device_id, plaintext)
```

`SatellitePacket` fields: `device_id`, `seq_num`, `device_type`, `timestamp`, `rssi_dB`, `channel_num`, `freq_offset_hz`, `payload` (bytes), `auth_tag` (bytes or `None`).

### Errors

| Exception | Cause |
|-----------|-------|
| `DockerError` | Docker not installed, daemon not running, or container failed to start |
| `SatelliteError` | Container started but receiver API did not become ready in time |

## Configuration

The **CLI** reads two environment variables:

* `HUBBLE_ORG_ID` — your organization id
* `HUBBLE_API_TOKEN` — your API token, passed through as a bearer token

```bash
export HUBBLE_ORG_ID=org_123
export HUBBLE_API_TOKEN=sk_XXXX
```

Every command that needs credentials also takes `--org-id` and `--token`, and
`--help` names the environment variable for each. On the `org` and `metrics`
groups those flags belong to the group, so they go before the subcommand:

```bash
hubblenetwork org --org-id <id> --token <token> list-devices
```

Check whichever route you used with `hubblenetwork validate-credentials`.

**The SDK does not read the environment.** `Organization()` requires its
credentials explicitly, so exporting the variables does nothing for library code:

```python
from hubblenetwork import Organization
import os

org = Organization(
    org_id=os.environ["HUBBLE_ORG_ID"],
    api_token=os.environ["HUBBLE_API_TOKEN"],
)
```

## Public API (summary)

Import from the package top-level for a stable surface:

```python
from hubblenetwork import (
    ble, cloud, ready, sat,
    Organization, Device, Credentials, Environment,
    EncryptedPacket, UnencryptedPacket, AesEaxPacket, UnknownPacket,
    DecryptedPacket, SatellitePacket, Location,
    decrypt, decrypt_eax, decrypt_satellite,
    UNIX_TIME, DEVICE_UPTIME,
    InvalidCredentialsError,
)
```

Key objects & functions:

* `Organization` provides credentials for performing cloud actions (e.g. registering devices, retrieving decrypted packets, retrieving devices, etc.)
* `EncryptedPacket` a packet that has not been decrypted (can be decrypted locally given a key or ingested to the backend)
* `DecryptedPacket` a packet that has been successfully decrypted either locally or by the backend.
* `SatellitePacket` a packet decoded by the satellite receiver (PlutoSDR).
* `Location` data about where a packet was seen.
* `ble.scan` function for locally scanning for devices with BLE.
* `sat.scan` generator for receiving satellite packets via PlutoSDR (requires Docker).
* `Organization.iter_devices()` / `iter_packets()` generators that yield as each API
  page arrives instead of accumulating, so you can start processing immediately on a
  device with tens of thousands of packets. Both take an optional
  `on_page(page, total_so_far)` callback. `list_devices()` and `retrieve_packets()`
  are `list()` wrappers over them and still return lists.

See code for full details.

## Development & tests

Set up a virtualenv and install dev deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Run linters:

```bash
ruff check src
```

## Troubleshooting

* **`ble.scan()` finds nothing**: verify BLE permissions and adapter state; try increasing `timeout`.
* **macOS: `ble scan` crashes instead of prompting for Bluetooth** — you'll see
  `Termination Reason: Namespace TCC` and a message about a missing
  `NSBluetoothAlwaysUsageDescription` key. macOS refuses CoreBluetooth to any
  executable without that key in an Info.plist, and Homebrew's `python3` binary has
  no Info.plist at all. Run from a real terminal app (Terminal, iTerm) rather than an
  embedded IDE shell and grant it Bluetooth under System Settings → Privacy &
  Security → Bluetooth. If it still aborts, run the CLI through a small app bundle
  that carries the key; the framework build at
  `$(brew --prefix)/Frameworks/Python.framework/Versions/<ver>/Resources/Python.app`
  is a usable starting point to copy and amend.
* **Auth errors**: confirm `Organization(org_id, api_token)` or env vars are set; check
  token scope/expiry. `hubblenetwork validate-credentials` reports which environment
  accepted them and exits 1 if neither did, so it is safe to use in a script.
* **Import errors**: ensure you installed into the Python you’re running (`python -m pip …`). Prefer `pipx` for CLI-only usage.
* **`DockerError: Docker is not available`**: Docker daemon is not running. Start Docker Desktop (macOS/Windows) or `sudo systemctl start docker` (Linux).
* **`DockerError: The ‘docker’ Python package is required`**: run `pip install docker` (it is bundled with `pyhubblenetwork` but may be missing in some environments).
* **`SatelliteError: Satellite receiver API did not become ready`**: the PlutoSDR container started but couldn’t access the hardware. Ensure the ADALM-PLUTO dongle is plugged in before running `sat scan`, and that no other process is using it.
* **`sat scan` hangs pulling the image**: first run fetches `ghcr.io/hubblenetwork/sdr-docker:latest`; this may take a minute on a slow connection. Subsequent runs use the cached image.


## Telemetry

**There is none.** The CLI makes no network call except the ones a command
explicitly needs: the Hubble Cloud API for `org` and `metrics`, `localhost` for the
satellite receiver container, and Docker pulling that container image from
`ghcr.io` on first `sat` use. Nothing is reported anywhere about how you use it.

If that changes, these are the constraints it would have to meet, recorded here so
the bar is set before anyone writes the code:

* **Opt-in only.** Off by default, no collection before an explicit yes, and no
  dark-pattern prompt that treats a dismissed dialog as consent.
* **Nothing sensitive, ever.** No API tokens, org IDs, device IDs, encryption keys,
  payloads, coordinates, hostnames, or file paths. This tool handles customer device
  keys, so the bar is higher than for a typical CLI. Command name, exit status, and
  version is the ceiling.
* **Documented in this file**, listing every field actually sent, not a link to a
  policy page.
* **Killable two ways**, a flag and an environment variable, both honoured on every
  command.
* **Never blocks or slows a command.** No network call on the critical path, and
  silent failure when offline.
* **Tested.** A test asserting the payload contains no credential and no device
  identifier, so a future field cannot quietly widen it.

## Releases & versioning

Follows **SemVer** (MAJOR.MINOR.PATCH). Pushing a version tag triggers a GitHub Actions workflow that runs tests, builds the package, creates a GitHub Release, and publishes to PyPI.

### Cutting a release

1. **Bump the version** in `pyproject.toml`:
   ```
   version = "0.6.0"
   ```

2. **Add release notes** to the top of `release-notes.md`:
   ```markdown
   ## [0.6.0] - 2026-04-01

   ### Added
   - feat(cli): new command description

   ### Fixed
   - fix(org): bug description
   ```

3. **Commit, tag, and push:**
   ```bash
   git add pyproject.toml release-notes.md
   git commit -m "chore: release 0.6.0"
   git push origin main
   git tag v0.6.0
   git push origin v0.6.0
   ```

4. **Approve the publish step** in the [GitHub Actions UI](https://github.com/HubbleNetwork/pyhubblenetwork/actions) (the `pypi` environment requires manual approval).

The workflow verifies the tag matches the version in `pyproject.toml`, so both must agree. PyPI publishing uses [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC) — no API tokens are stored in the repo.
