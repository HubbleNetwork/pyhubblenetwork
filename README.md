# pyhubblenetwork

[![PyPI](https://img.shields.io/pypi/v/pyhubblenetwork.svg)](https://pypi.org/project/pyhubblenetwork)
[![Python](https://img.shields.io/pypi/pyversions/pyhubblenetwork.svg)](https://pypi.org/project/pyhubblenetwork)
[![License](https://img.shields.io/github/license/HubbleNetwork/pyhubblenetwork)](LICENSE)

**`hubblenetwork` is the command-line tool for Hubble Network IoT devices.** Watch
nearby devices report over Bluetooth, receive their packets from satellite, decrypt
payloads locally with a device key, and manage your fleet in the Hubble Cloud — no
embedded firmware knowledge required.

It is also an importable Python SDK: everything the CLI does is available as a
library. See [Using it as a Python library](#using-it-as-a-python-library).

Links: [PyPI](https://pypi.org/project/pyhubblenetwork/) ·
[Hubble docs](https://docs.hubble.com/docs/intro) ·
[Embedded SDK](https://github.com/HubbleNetwork/sdk)


## Install

```bash
pip install pyhubblenetwork

# or, for CLI-only use, into its own environment:
pipx install pyhubblenetwork
```

Set your credentials, then check the machine is actually able to do the work:

```bash
export HUBBLE_ORG_ID=<your org id>
export HUBBLE_API_TOKEN=<your api token>
hubblenetwork doctor
```

`doctor` is the setup step. It checks credentials, Bluetooth and Docker, and names
the fix for anything broken:

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


## What do you want to do?

| Goal | Command |
|------|---------|
| Check my setup is working | [`doctor`](#install) |
| Watch nearby devices report | [`ble scan`](#watch-nearby-devices-report) |
| Prove one device works end to end | [`ble validate`](#prove-one-device-works-end-to-end) |
| See what's registered to my org | [`org list-devices`](#work-with-your-fleet-in-the-cloud) |
| Read a device's history from the cloud | [`org get-packets <id>`](#work-with-your-fleet-in-the-cloud) |
| Register a new device and get its key | [`org register-device`](#work-with-your-fleet-in-the-cloud) |
| Receive packets from satellite | [`sat scan`](#receive-satellite-packets) |
| Capture raw RF for offline analysis | [`sat record`](#one-shot-capture-record--signal-report) |

Reference: [Reading the output](#reading-the-output) ·
[Configuration](#configuration) ·
[Requirements](#requirements) ·
[Python library](#using-it-as-a-python-library) ·
[Troubleshooting](#troubleshooting)

Every command lives inside a group, so it is always `hubblenetwork <group> <command>`:

* **`org`** — your devices in the Hubble Cloud
* **`ble`** — nearby devices over Bluetooth
* **`sat`** — satellite packets via PlutoSDR
* **`metrics`** — fleet counts

`hubblenetwork --help` prints the full list with a one-line description and the
required arguments for each, and every command takes `--help` for its own options.


## Watch nearby devices report

`ble scan` listens for Hubble beacon advertisements (UUID 0xFCA6) and prints one line
per packet as it arrives. No credentials needed — this is purely local.

```bash
hubblenetwork ble scan
```

It runs until Ctrl+C unless you bound it. Pass `--key` and the payloads are decrypted
locally as they arrive.

| Flag | Takes | Description |
|------|-------|-------------|
| `-t`, `--timeout` | seconds | Stop after this long. Default: no timeout. |
| `-n`, `--count` | N | Stop after N packets. |
| `-k`, `--key` | hex or base64, 16 or 32 bytes | Decrypt payloads locally with this device key. |
| `--show-failed-decryption` | — | Also show packets the key can't decrypt, with a `✓`/`✗` mark per row. Off by default, so they are hidden. |
| `--counter-mode` | `UNIX_TIME` or `DEVICE_UPTIME` | EID counter source for AES-CTR packets. Default: `UNIX_TIME`. |
| `-d`, `--days` | N | Days to search when decrypting AES-CTR packets in `UNIX_TIME` mode. Default: 2. |
| `-e`, `--period-exponent` | 0-15 | EID rotation period for AES-EAX packets; period = 2ⁿ seconds. Matches `rot_exp` in the device config. Default: 0. |
| `--network-id` | 34-bit ID | Show only this network. Unencrypted protocol only. |
| `--ingest` | — | Relay received packets to the Hubble Cloud. Needs `--key` and credentials. |
| `--org-id` | ID | Organization ID for `--ingest`. Env: `HUBBLE_ORG_ID`. |
| `--token` | token | API token for `--ingest`. Env: `HUBBLE_API_TOKEN`. |
| `-o`, `--format` | `tabular` or `json` | Output format. Default: `tabular`. |
| `--payload-format` | `auto`, `base64`, `hex`, `string` | How to render payloads — see [Payload format](#payload-format). |
| `--debug` | — | Add the `EPOCH`, `TAG` and `SALT` forensic columns. |


## Prove one device works end to end

`ble validate` is the quickest way to answer "is my device working?". It walks the
whole chain — your credentials, the device's registration, its advertisements, the
key, and the cloud round trip — and stops at the first failure.

It validates the **terrestrial** path: the device advertising over Bluetooth, this
machine acting as the gateway, and the packet reaching the cloud and coming back. It
says nothing about whether the device is reaching the satellite network — for that,
receive it directly with [`sat scan`](#receive-satellite-packets).

```bash
hubblenetwork ble validate \
  --key "a562a2f7e4c62bed52ab09633878f62b" \
  --device-id "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"
```

The steps, in order:

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


## Work with your fleet in the cloud

The `org` group talks to the Hubble Cloud, so it needs credentials.

```bash
hubblenetwork org info                      # which org and environment am I on?
hubblenetwork org list-devices              # everything registered
hubblenetwork org list-devices -n 20
hubblenetwork org list-devices -f json      # machine-readable

hubblenetwork org get-packets <id>          # last 7 days by default
hubblenetwork org get-packets <id> --days 30 --format csv
hubblenetwork org get-packets <id> -n 50 --debug

hubblenetwork org register-device           # returns the new device's key
hubblenetwork org set-device-name <id> <name>
hubblenetwork org delete-device <id>
```

`list-devices` and `get-packets` stream rows as pages arrive, so the first rows appear
in about a second rather than after the whole window downloads. A busy device can hold
tens of thousands of packets; Ctrl+C stops early and still prints a summary, and
`--limit`/`-n` caps the run. It always says how it stopped, never silently.

`register-device` takes `--encryption`, `--counter-source`, and — for AES-128-EAX on
`DEVICE_UPTIME` — either `--period-seconds` or `--period-exponent` (period = 2ⁿ
seconds; the cloud accepts 10-15, default 15 ≈ 9h). The two period flags are mutually
exclusive.


## Receive satellite packets

The `sat` group receives packets through a PlutoSDR dongle. It runs a Docker container
([`ghcr.io/hubblenetwork/sdr-docker`](https://ghcr.io/hubblenetwork/sdr-docker)) that
handles RF reception and decoding, polls that container's HTTP API, and streams
decoded packets to stdout.

**Needs Docker running and an ADALM-PLUTO plugged in over USB.** `hubblenetwork doctor`
checks the Docker half.

```bash
# Stream packets until Ctrl+C
hubblenetwork sat scan

# Bounded runs
hubblenetwork sat scan --timeout 30
hubblenetwork sat scan -n 5
hubblenetwork sat scan -o json --timeout 60 -n 20

# Decrypt payloads locally with a device key
hubblenetwork sat scan --key "a562a2f7e4c62bed52ab09633878f62b"
hubblenetwork sat scan --key "<key>" --counter-mode DEVICE_UPTIME
hubblenetwork sat scan --key "<key>" --show-failed-decryption

# No hardware to hand? Stream fake packets
hubblenetwork sat mock-scan
```

Decryption uses the same AES-CTR scheme as BLE and supports both counter sources. The
source is auto-detected from the packets and announced, unless `--counter-mode` is
given. For `UNIX_TIME`, `--days` controls how many days around each packet's timestamp
are searched (default 2). Packets the key cannot decrypt are hidden unless
`--show-failed-decryption` is given.

`sat scan` handles the container for you: it verifies Docker, pulls the image if it
isn't cached, starts the container privileged so it can reach USB, waits for the
receiver API and for the SDR to connect, deduplicates packets by device ID and
sequence number, then stops and removes the container on exit.

### One-shot capture (`record` / `signal-report`)

Alongside the live stream, two commands record for a fixed duration, save a single
file, and exit. Both accept `--output PATH` (default: an auto-generated timestamped
name), `--mock` (use the simulated receiver — no PlutoSDR required), `--pluto-uri`,
and `--debug`.

```bash
# Capture 10 s of raw IQ samples to a .npy file
hubblenetwork sat record 10
hubblenetwork sat record 10 --output capture.npy

# Record 10 s and save an RF signal-diagnostic report to a .txt file
hubblenetwork sat signal-report 10
hubblenetwork sat signal-report 10 --output report.txt --mock
```

- **`record`** captures the raw radio signal only — no decoding. The output is a
  NumPy `.npy` file of IQ samples.
- **`signal-report`** records IQ, then re-analyzes it offline into a plain-text
  **link-health diagnostic**: per-symbol timing/drift, channel-hopping validation,
  amplitude/SNR, and chipset metrics. It reports on signal quality and does **not**
  contain decoded packet payloads — to receive payloads, use `sat scan --key`.


## Reading the output

### Payload format

Commands that print packet data (`ble scan`, `sat scan`, `ble detect`,
`org get-packets`) take `--payload-format`:

* `auto` — printable ASCII shows as text, anything else as uppercase hex
* `base64` — encode payloads as base64
* `hex` — display payloads as hexadecimal
* `string` — decode payloads as UTF-8 (falls back to `<invalid UTF-8>`)

All four work with every output format, but the **default** differs, because a person
and a program want different things. Tabular output defaults to `auto`, so a decrypted
payload reads as `T=21.4` rather than `VD0yMS40`. JSON and CSV default to `base64` so
the machine contract stays stable. An explicit `--payload-format` always wins.

### Scan layout

`ble scan` and `sat scan` print one line per packet with a signal bar, and close with
a summary:

```
    TIME     RSSI       V EID              CTR/SEQ PAYLOAD
─────────────────────────────────────────────────────────────────────────────
✓   00:06:40  -62 ███▏  2 9c4e2ab77d3f0e1a   20320 T=21.4,B=87
✓   00:06:43  -66 ██▉   2 9c4e2ab77d3f0e1b   20321 T=21.4,B=87
✗   00:06:49  -74 ██▏   2 9c4e2ab77d3f0e1d       - D307912C66BA4018E5
─────────────────────────────────────────────────────────────────────────────

4 packets  ·  3 decrypted, 1 failed  ·  RSSI -62 to -74 dBm  ·  12s
```

The bar next to RSSI is signal strength: length is the magnitude, so you can watch it
shrink as you walk away from a device. The `✓`/`✗` mark only appears with
`--show-failed-decryption`, and it carries the state on its own, so the output still
reads correctly without colour.

Packet rows go to **stdout** and everything else — the scanning notice, detection
lines, the summary — goes to **stderr**, so this captures data only:

```bash
hubblenetwork ble scan > packets.txt
```

The same split applies to `org list-devices` and `org get-packets`.

Pass `--debug` for the forensic columns: `EPOCH`, `TAG` and `SALT` on `ble scan`,
`RS_CORR`, `SYM_MS` and `GAP_MS` on `sat scan`, `EPOCH`, `CTR` and `SEQ` on
`org get-packets`.

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
double-width one. `--no-ascii` forces the Unicode rendering if the detection is wrong
for you.

Colour is a separate axis: `--no-color`, `NO_COLOR=1`, or a non-TTY stdout all disable
it, and `FORCE_COLOR=1` keeps it on where a pipe would otherwise strip it (useful in
CI). Both flags work on any command, before or after the subcommand.


## Configuration

The CLI reads two environment variables:

* `HUBBLE_ORG_ID` — your organization id
* `HUBBLE_API_TOKEN` — your API token, passed through as a bearer token

```bash
export HUBBLE_ORG_ID=org_123
export HUBBLE_API_TOKEN=sk_XXXX
```

Every command that needs credentials also takes `--org-id` and `--token`, and `--help`
names the environment variable for each. On the `org` and `metrics` groups those flags
belong to the group, so they go before the subcommand:

```bash
hubblenetwork org --org-id <id> --token <token> list-devices
```

Check whichever route you used with `hubblenetwork validate-credentials` or
`hubblenetwork doctor`.

**The SDK does not read the environment** — see below.


## Requirements

- Python **3.10+** (3.11/3.12 recommended)
- **Bluetooth**, for the `ble` group:
  - **macOS**: CoreBluetooth. Run from a real terminal app and grant it Bluetooth
    access when prompted. macOS kills any process whose executable has no
    `NSBluetoothAlwaysUsageDescription` in an Info.plist, and a bare Python binary
    has none — see [Troubleshooting](#troubleshooting) if you hit a crash rather
    than a permission prompt.
  - **Linux**: BlueZ required; the user must have permission to access the BLE
    adapter (often the `bluetooth` group).
  - **Windows**: a compatible BLE stack/adapter.
- **Docker and a PlutoSDR**, for the `sat` group:
  [Docker Desktop](https://www.docker.com/get-started/) (macOS/Windows) or Docker
  Engine (Linux) installed and running, and an Analog Devices ADALM-PLUTO connected
  over USB. `sat mock-scan`, `sat record --mock` and `sat signal-report --mock` need
  Docker but no SDR.

`hubblenetwork doctor` reports on all of this.


## Using it as a Python library

Everything the CLI does is available as a library. Import from the package top-level
for a stable surface:

```python
from hubblenetwork import (
    ble, cloud, sat,
    Organization, Device, Credentials, Environment,
    EncryptedPacket, UnencryptedPacket, AesEaxPacket, UnknownPacket,
    DecryptedPacket, SatellitePacket, Location,
    decrypt, decrypt_eax, decrypt_satellite,
    UNIX_TIME, DEVICE_UPTIME,
    InvalidCredentialsError,
)
```

**Unlike the CLI, the SDK does not read the environment.** `Organization()` requires
its credentials explicitly:

```python
import os
from hubblenetwork import Organization

org = Organization(
    org_id=os.environ["HUBBLE_ORG_ID"],
    api_token=os.environ["HUBBLE_API_TOKEN"],
)

new_dev = org.register_device()           # returns a Device, with its key
for d in org.iter_devices():              # streams as pages arrive
    print(d.id, d.name)
for pkt in org.iter_packets(new_dev):     # ditto; both take on_page(page, total)
    print(pkt.rssi, pkt.payload)
```

`iter_devices()` and `iter_packets()` are generators that yield as each API page
arrives instead of accumulating, so you can start processing immediately on a device
with tens of thousands of packets. `list_devices()` and `retrieve_packets()` are
`list()` wrappers over them and still return lists.

Scanning and local decryption:

```python
from hubblenetwork import ble, decrypt

for pkt in ble.scan(timeout=5.0):
    plaintext = decrypt(key, pkt)                            # UNIX_TIME by default
    plaintext = decrypt(key, pkt, counter_mode="DEVICE_UPTIME")
    if plaintext:
        print(plaintext.payload)
```

`counter_mode` accepts `"UNIX_TIME"` (default, UTC day-based) or `"DEVICE_UPTIME"`
(counter values 0–127, fixed pool size of 128). BLE and provisioning functions each
have sync and async variants — `ble.scan()` / `ble.scan_async()`.

Satellite, which manages the Docker container for you:

```python
from hubblenetwork import sat, SatellitePacket, decrypt_satellite

for pkt in sat.scan(timeout=60.0, poll_interval=2.0):
    print(pkt.device_id, pkt.seq_num, pkt.rssi_dB, pkt.payload.hex())
    if pkt.auth_tag is not None:
        plaintext = decrypt_satellite(
            key, seq_no=pkt.seq_num, auth_tag=pkt.auth_tag,
            encrypted_payload=pkt.payload, timestamp=pkt.timestamp,
            counter_mode="UNIX_TIME",
        )

packets: list[SatellitePacket] = sat.fetch_packets()   # current buffer, no lifecycle
iq_bytes: bytes = sat.record(10.0)                     # raw IQ (.npy file body)
report: str = sat.signal_report(10.0)                  # plain-text RF diagnostic
```

`SatellitePacket` fields: `device_id`, `seq_num`, `device_type`, `timestamp`,
`rssi_dB`, `channel_num`, `freq_offset_hz`, `payload` (bytes), `auth_tag` (bytes or
`None`). `sat.scan()` raises `DockerError` if Docker isn't available, and
`SatelliteError` if the container starts but the receiver API or the SDR never comes
up.

See the code for the full surface.


## Troubleshooting

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
* **`ble scan` finds nothing**: verify BLE permissions and adapter state, and try a
  longer `--timeout`. Slow advertising intervals plus OS-level scan optimizations mean
  a second attempt often succeeds.
* **Auth errors**: run `hubblenetwork doctor`. `validate-credentials` reports which
  environment accepted them and exits 1 if neither did, so it is safe in a script.
* **Import errors**: ensure you installed into the Python you're running
  (`python -m pip …`). Prefer `pipx` for CLI-only usage.
* **`DockerError: Docker is not available`**: the Docker daemon is not running. Start
  Docker Desktop (macOS/Windows) or `sudo systemctl start docker` (Linux).
* **`DockerError: The 'docker' Python package is required`**: run `pip install docker`
  (it ships with `pyhubblenetwork` but may be missing in some environments).
* **`SatelliteError: No PlutoSDR detected`**: the container started but the SDR never
  connected. Ensure the ADALM-PLUTO is plugged in before running `sat scan`, and that
  no other process is using it.
* **`sat scan` hangs pulling the image**: the first run fetches
  `ghcr.io/hubblenetwork/sdr-docker:latest`, which may take a minute on a slow
  connection. Later runs use the cached image.


## Development & tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

ruff check src
pytest
```


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

Follows **SemVer**. Pushing a `vX.Y.Z` tag triggers a GitHub Actions workflow that
runs tests, builds the package, creates a GitHub Release, and publishes to PyPI via
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — no API tokens are
stored in the repo. The `pypi` environment requires manual approval in the
[Actions UI](https://github.com/HubbleNetwork/pyhubblenetwork/actions).

To cut a release, use the `/release` skill: it bumps `pyproject.toml`, generates
notes into `release-notes.md` from the conventional-commit log, commits, tags, and
pushes.
