# pyhubblenetwork

[![PyPI](https://img.shields.io/pypi/v/pyhubblenetwork.svg)](https://pypi.org/project/pyhubblenetwork)
[![Python](https://img.shields.io/pypi/pyversions/pyhubblenetwork.svg)](https://pypi.org/project/pyhubblenetwork)
[![License](https://img.shields.io/github/license/HubbleNetwork/pyhubblenetwork)](LICENSE)

**`hubblenetwork` is the command-line tool for Hubble Network IoT devices.** Watch
nearby devices report over Bluetooth, pick their satellite uplink off the air with an
SDR, decrypt payloads locally with a device key, and manage your fleet in the Hubble
Cloud — no embedded firmware knowledge required. Everything it does is also available
as an importable [Python SDK](#using-it-as-a-python-library).

Links: [PyPI](https://pypi.org/project/pyhubblenetwork/) ·
[Hubble docs](https://docs.hubble.com/docs/intro) ·
[Embedded SDK](https://github.com/HubbleNetwork/sdk)


## Install

```bash
pip install pyhubblenetwork

# or, for CLI-only use, into its own environment:
pipx install pyhubblenetwork
```


## Check your setup with `doctor`

```bash
export HUBBLE_ORG_ID=<your org id>
export HUBBLE_API_TOKEN=<your api token>
hubblenetwork doctor
```

`doctor` checks credentials, Bluetooth, Docker and the cached satellite receiver
image, and names the fix for anything broken:

```
  ✗ Credentials    not set
      Set both, or pass --org-id/--token:
        export HUBBLE_ORG_ID=<your org id>
        export HUBBLE_API_TOKEN=<your api token>
  ✓ Bluetooth      usage description present
  ✗ Docker         Docker is not available
      Only `sat` commands need Docker.

Not ready.  ·  1 ok  ·  2 failed
```

It exits 1 when something needed is broken, so a script can gate on it. A skipped
check is not a failure: it means the check does not apply on this platform, or could
not be answered without doing real work (pulling the satellite receiver image, say).


## What do you want to do?

| Goal | Command |
|------|---------|
| Check my setup is working | [`doctor`](#check-your-setup-with-doctor) |
| Watch nearby devices report | [`ble scan`](#watch-nearby-devices-report) |
| Prove one device works end to end | [`ble validate`](#prove-one-device-works-end-to-end) |
| See what's registered to my org | [`org list-devices`](#work-with-your-fleet-in-the-cloud) |
| Read a device's history from the cloud | [`org get-packets <id>`](#work-with-your-fleet-in-the-cloud) |
| Register a new device and get its key | [`org register-device`](#work-with-your-fleet-in-the-cloud) |
| Hear a device's satellite uplink | [`sat scan`](#receive-a-devices-satellite-uplink) |
| Capture raw RF for offline analysis | [`sat record`](#one-shot-capture-record--signal-report) |

Reference: [Reading the output](#reading-the-output) ·
[Configuration](#configuration) ·
[Requirements](#requirements) ·
[Python library](#using-it-as-a-python-library) ·
[Troubleshooting](#troubleshooting)

Commands live in groups — **`org`** (your devices in the Hubble Cloud), **`ble`**
(nearby devices over Bluetooth), **`sat`** (satellite packets via PlutoSDR) and
**`metrics`** (fleet counts) — so it is usually `hubblenetwork <group> <command>`. The
two setup commands, `doctor` and `validate-credentials`, sit at the top level.

`hubblenetwork --help` lists everything; every command takes `--help` for its own
options. You don't have to remember which group a command is in: type one at the wrong
level and the CLI searches the whole tree and points you at it (`Did you mean:
hubblenetwork org list-devices`). Missing arguments say how to find the value, unknown
options list what the command accepts, and missing credentials name the environment
variables and the flags.


## Watch nearby devices report

`ble scan` listens for Hubble beacon advertisements (UUID 0xFCA6) and prints one line
per packet as it arrives. No credentials needed — this is purely local. It runs until
Ctrl+C unless you bound it.

```bash
hubblenetwork ble scan
```

| Flag | Takes | Description |
|------|-------|-------------|
| `-t`, `--timeout` | seconds | Stop after this long. Default: no timeout. |
| `-n`, `--count` | N | Stop after N packets. |
| `-k`, `--key` | hex or base64, 16 or 32 bytes | Decrypt payloads locally with this device key. |
| `--show-failed-decryption` | — | Also show packets the key can't decrypt, with a `✓`/`✗` mark per row. Off by default, so they are hidden. |
| `--counter-mode` | `UNIX_TIME` or `DEVICE_UPTIME` | EID counter source for AES-CTR packets. Omit it to auto-detect — see below. |
| `-d`, `--days` | N | Days to search when decrypting AES-CTR packets in `UNIX_TIME` mode. Default: 2. |
| `-e`, `--period-exponent` | 0-15 | EID rotation period for AES-EAX packets; period = 2ⁿ seconds. Matches `rot_exp` in the device config. Omit it to auto-detect — see below. |
| `--network-id` | 34-bit ID | Show only this network. Unencrypted protocol only. |
| `--ingest` | — | Relay decrypted packets to the Hubble Cloud. Without `--key` nothing is ingested. Needs credentials. |
| `--org-id` | ID | Organization ID for `--ingest`. Env: `HUBBLE_ORG_ID`. |
| `--token` | token | API token for `--ingest`. Env: `HUBBLE_API_TOKEN`. |
| `-o`, `--format` | `tabular` or `json` | Output format. Default: `tabular`. |
| `--payload-format` | `auto`, `base64`, `hex`, `string` | How to render payloads — see [Payload format](#payload-format). |
| `--debug` | — | Add the `EPOCH`, `TAG` and `SALT` forensic columns. |

With `--key` and neither `--counter-mode` nor `--period-exponent` given, the
decryption strategy is worked out from the packets themselves, so you don't have to
know how the device was provisioned. The first packet that decrypts prints what it
found, once, on stderr — `[INFO] Detected: AES-256-CTR,
counter_source=DEVICE_UPTIME`. Passing either flag pins that half of the detection and
skips its sweep.

`--counter-mode DEVICE_UPTIME` requires `--key` and cannot be combined with `--days`,
which only means something for the day-based `UNIX_TIME` counter; both are rejected
with a usage error rather than quietly ignored. `sat scan` behaves the same way.


## Prove one device works end to end

`ble validate` is the quickest way to answer "is my device working?". It walks the
whole chain and stops at the first failure: key and device-ID formats → credentials →
organization → the device's registration → BLE advertisements → decrypting a packet
(reporting the EID type as `UNIX_TIME`, `DEVICE_UPTIME`, or `AMBIGUOUS` when a packet
resolves under both, usually several devices in range with different configs) →
ingesting it and reading it back.

```bash
hubblenetwork ble validate \
  --key "a562a2f7e4c62bed52ab09633878f62b" \
  --device-id "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"
```

| Option | Description |
|--------|-------------|
| `--key`, `-k` | Device key, used to test packet encryption (required). Accepts hex or base64, 16- or 32-byte. |
| `--device-id`, `-d` | Device UUID, used to test the backend (required). |
| `--org-id` | Organization ID (defaults to the `HUBBLE_ORG_ID` env var). |
| `--token` | API token (defaults to the `HUBBLE_API_TOKEN` env var). |
| `--timeout`, `-t` | BLE scan timeout in seconds (default: 30). |

This is the **terrestrial** path only — the device advertising over Bluetooth, this
machine as the gateway, and the round trip through the cloud. It says nothing about
whether the device is reaching the satellite network; for that, hear the uplink
yourself with [`sat scan`](#receive-a-devices-satellite-uplink).

A failing step prints targeted debugging tips. A failed scan is often just a slow
advertising interval meeting OS-level BLE scan optimizations — running it again
usually resolves it.

Two narrower checks sit alongside it, both reading advertisements rather than the
cloud: `ble check-time -k <key>` reports how many days a device's clock is off real
UTC (more than 2 is out of spec), and `ble detect -k <key>` answers just the "which
EID mode is this key using?" question that `ble scan` folds into its auto-detection.


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

In tabular output, `list-devices` and `get-packets` stream rows as pages arrive, so
the first rows appear in about a second rather than after the whole window downloads.
A busy device can hold tens of thousands of packets; Ctrl+C stops early and still
prints a summary, `--limit`/`-n` caps the run, and it always says how it stopped.

`-o json` and `-o csv` keep their byte-for-byte output, so they buffer the whole
result and print no summary. For `get-packets`, `--limit` then trims after the
download rather than stopping it — `-n 50 -o json` still fetches the full window. Use
tabular output when you want the run itself bounded.

`register-device` takes `--encryption`, `--counter-source`, and — for AES-128-EAX on
`DEVICE_UPTIME` — either `--period-seconds` or `--period-exponent` (period = 2ⁿ
seconds; the cloud accepts 10-15, default 15 ≈ 9h). The two period flags are mutually
exclusive.


## Receive a device's satellite uplink

The `sat` group listens, on the ground, to the transmissions a device sends up to the
satellite network. Nothing is received *from* a satellite: a PlutoSDR beside you picks
the uplink out of the air, confirming the device is transmitting on the satellite path
at all.

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

Decryption uses the same AES-CTR scheme as BLE, with the counter source auto-detected
and announced unless `--counter-mode` is given. `--days` (default 2) controls how many
days around each packet's timestamp are searched in `UNIX_TIME` mode, and packets the
key cannot decrypt are hidden unless `--show-failed-decryption` is given.

`sat scan` handles the Docker container
([`ghcr.io/hubblenetwork/sdr-docker`](https://ghcr.io/hubblenetwork/sdr-docker)) for
you: it verifies Docker, pulls the image if it isn't cached, starts the container
privileged so it can reach USB, waits for the receiver API and the SDR, polls the
container's HTTP API and deduplicates by device ID and sequence number, then stops and
removes the container on exit.

### One-shot capture (`record` / `signal-report`)

Two commands record for a fixed duration, save a single file, and exit. Both accept
`--output PATH` (default: an auto-generated timestamped name), `--mock` (simulated
receiver — no PlutoSDR required), `--pluto-uri`, and `--debug`.

```bash
# Capture 10 s of raw IQ samples to a .npy file
hubblenetwork sat record 10
hubblenetwork sat record 10 --output capture.npy

# Record 10 s and save an RF signal-diagnostic report to a .txt file
hubblenetwork sat signal-report 10
hubblenetwork sat signal-report 10 --output report.txt --mock
```

- **`record`** captures the raw radio signal only — no decoding. Output is a NumPy
  `.npy` file of IQ samples.
- **`signal-report`** records IQ, then re-analyzes it offline into a plain-text
  **link-health diagnostic**: per-symbol timing/drift, channel-hopping validation,
  amplitude/SNR, chipset metrics. It holds no decoded payloads — for those, use
  `sat scan --key`.


## Reading the output

### Payload format

Commands that print packet data (`ble scan`, `sat scan`, `ble detect`,
`org get-packets`) take `--payload-format`:

* `auto` — printable ASCII shows as text, anything else as uppercase hex
* `base64` — encode payloads as base64
* `hex` — display payloads as hexadecimal
* `string` — decode payloads as UTF-8 (falls back to `<invalid UTF-8>`)

All four work with every output format, but the **default** differs: tabular output
defaults to `auto`, so a decrypted payload reads as `T=21.4` rather than `VD0yMS40`,
while JSON and CSV default to `base64` so the machine contract stays stable. An
explicit `--payload-format` always wins.

### Scan layout

`ble scan` and `sat scan` print one line per packet with a signal bar, and close with
a summary:

```
    TIME     RSSI       V EID              CTR/SEQ PAYLOAD
─────────────────────────────────────────────────────────────────────────────
✓   00:06:40  -62 ███▏  0 9c4e2ab7           20693 T=21.4,B=87
✓   00:06:43  -66 ██▉   0 9c4e2ab7           20693 T=21.4,B=87
✗   00:06:49  -74 ██▏   0 51d7be04             302 D307912C66BA4018E5
─────────────────────────────────────────────────────────────────────────────

3 packets  ·  2 decrypted, 1 failed  ·  RSSI -62 to -74 dBm  ·  12s
```

The bar's length is signal magnitude, so you can watch it shrink as you walk away from
a device. The `✓`/`✗` mark only appears with `--show-failed-decryption`, and it carries
the state on its own, so the output still reads correctly without colour.

`V` is the protocol version, and it decides what the two columns after it hold:

* **`0`, AES-CTR** — a 4-byte EID, and a `CTR/SEQ` showing the day counter once a
  packet decrypts (`20693` above) or the advertisement's own sequence number when it
  doesn't (`302`).
* **`1`, unencrypted** — no EID at all, so a `NET_ID` column takes that space.
* **`2`, AES-EAX** — an 8-byte EID, and a `CTR/SEQ` that stays `-`: its only
  counter-shaped value is a random per-message nonce salt, which has its own `SALT`
  column under `--debug`.

Packet rows go to **stdout** and everything else — the scanning notice, detection
lines, the summary — goes to **stderr**, so `hubblenetwork ble scan > packets.txt`
captures data only. The same split applies to `org list-devices` and
`org get-packets`.

Pass `--debug` for the forensic columns: `EPOCH`, `TAG` and `SALT` on `ble scan`,
`RS_CORR`, `SYM_MS` and `GAP_MS` on `sat scan`, `EPOCH`, `CTR` and `SEQ` on
`org get-packets`.

### Terminals that can't do box-drawing

Not every terminal can render `─` and `█`: a legacy code page raises
`UnicodeEncodeError`, and a CJK configuration renders them double-width, which shears
every column. Pass `--ascii` (or set `HUBBLE_ASCII=1`) for a pure-ASCII rendering with
identical column widths — every substitution is the same display width as the glyph it
replaces. Only the bar's precision changes: ASCII has no sub-cell fill, so the eight
partial blocks collapse to one `=` tier and two nearby readings can land on the same
bar. The exact dBm is in the column beside it.

The encoding case is detected automatically, so you only need the flag for the
double-width one; `--no-ascii` forces the Unicode rendering back.

Colour is a separate axis: `--no-color`, a non-empty `NO_COLOR`, or a non-TTY stdout
all disable it, and `FORCE_COLOR` keeps it on where a pipe would otherwise strip it
(useful in CI). Both flags work on any command, before or after the subcommand.


## Configuration

Two environment variables carry your credentials:

```bash
export HUBBLE_ORG_ID=org_123     # your organization id
export HUBBLE_API_TOKEN=sk_XXXX  # passed through as a bearer token
```

Four more change how the CLI behaves, and none of them are required:

| Variable | Effect |
|----------|--------|
| `HUBBLE_ASCII` | `1`/`true`/`yes`/`on` forces the ASCII rendering; `0`/`false`/`no`/`off` forces Unicode. Same as `--ascii`/`--no-ascii`, which win over it. |
| `NO_COLOR` | Any non-empty value disables colour, per [no-color.org](https://no-color.org). |
| `FORCE_COLOR` | Any non-empty value keeps colour on where a pipe would otherwise strip it. |
| `SDR_DOCKER_IMAGE` | Overrides the satellite receiver image. Default: `ghcr.io/hubblenetwork/sdr-docker:latest`. |

Every command that needs credentials also takes `--org-id` and `--token`, and `--help`
names the environment variable for each. On the `org` and `metrics` groups those flags
belong to the group, so they go before the subcommand:

```bash
hubblenetwork org --org-id <id> --token <token> list-devices
```

Check whichever route you used with `hubblenetwork validate-credentials` or
`hubblenetwork doctor`. **The SDK does not read the environment** — see below.


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

Import from the package top-level for a stable surface:

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

The iterators yield as each API page arrives instead of accumulating, so you can start
processing immediately on a device with tens of thousands of packets.
`list_devices()` and `retrieve_packets()` are `list()` wrappers over them.

`ble.scan()` returns a mixed list — the unencrypted protocol and AES-EAX have their
own packet types — so filter to `EncryptedPacket` before handing anything to
`decrypt()`, which only understands AES-CTR. It returns `None` rather than raising on
a packet it can't handle, so an unfiltered loop looks like a wrong key:

```python
from hubblenetwork import ble, decrypt, decrypt_eax, AesEaxPacket, EncryptedPacket

key = bytes.fromhex("a562a2f7e4c62bed52ab09633878f62b")

for pkt in ble.scan(timeout=5.0):
    if isinstance(pkt, EncryptedPacket):                      # AES-CTR
        decrypted = decrypt(key, pkt)                         # UNIX_TIME by default
        # decrypted = decrypt(key, pkt, counter_mode="DEVICE_UPTIME")
    elif isinstance(pkt, AesEaxPacket):
        decrypted = decrypt_eax(key, pkt, period_exponent=0)
    else:
        continue                                              # nothing to decrypt
    if decrypted:
        print(decrypted.payload)                              # a DecryptedPacket
```

`counter_mode` accepts `"UNIX_TIME"` (default, UTC day-based) or `"DEVICE_UPTIME"`
(counter values 0–127, fixed pool size of 128). The BLE functions have sync and async
variants — `ble.scan()` / `ble.scan_async()`. The CLI's auto-detection is available
too, in `hubblenetwork.detect`: `detect_eid_type()` classifies a key's rotation mode
from a batch of packets, and `CtrCounterModeDetector` / `EaxExponentDetector` are the
per-scan objects that own the sweep and its cache.

Satellite, which manages the Docker container for you:

```python
from hubblenetwork import sat, SatellitePacket, decrypt_satellite

key = bytes.fromhex("a562a2f7e4c62bed52ab09633878f62b")

for pkt in sat.scan(timeout=60.0, poll_interval=2.0):
    print(pkt.device_id, pkt.seq_num, pkt.rssi_dB, pkt.payload.hex())
    if pkt.auth_tag is not None:
        plaintext: bytes | None = decrypt_satellite(
            key, seq_no=pkt.seq_num, auth_tag=pkt.auth_tag,
            encrypted_payload=pkt.payload, timestamp=pkt.timestamp,
            counter_mode="UNIX_TIME",
        )

packets: list[SatellitePacket] = sat.fetch_packets()   # current buffer, no lifecycle
iq_bytes: bytes = sat.record(10.0)                     # raw IQ (.npy file body)
report: str = sat.signal_report(10.0)                  # plain-text RF diagnostic
```

The return types differ: `decrypt()` and `decrypt_eax()` hand back a
`DecryptedPacket`, while `decrypt_satellite()` hands back plaintext `bytes` directly,
because a satellite packet's metadata never left the `SatellitePacket` you already
have. Both return `None` on failure.

`SatellitePacket` fields: `device_id`, `seq_num`, `device_type`, `timestamp`,
`rssi_dB`, `channel_num`, `freq_offset_hz`, `payload` (bytes), `auth_tag` (bytes or
`None`), plus four optional receiver diagnostics that back the `--debug` columns —
`pdu_n_corr` and `header_n_corr` (Reed-Solomon corrections, `RS_CORR`), `sym_mean_ms`
(`SYM_MS`) and `gap_mean_ms` (`GAP_MS`).

The two satellite exceptions live in `hubblenetwork.errors` rather than the top-level
surface. `sat.scan()` raises `DockerError` when Docker is missing, not running, or the
container fails to start, and `SatelliteError` when the container starts but the
receiver API or the SDR never comes up. Both descend from `HubbleError`, alongside the
backend, network, validation, BLE and decryption errors in the same module.

```python
from hubblenetwork.errors import DockerError, SatelliteError
```


## Troubleshooting

* **macOS: `ble scan` crashes instead of prompting for Bluetooth** (`Termination
  Reason: Namespace TCC`, missing `NSBluetoothAlwaysUsageDescription`) — macOS refuses
  CoreBluetooth to any executable without that key in an Info.plist, and Homebrew's
  `python3` has no Info.plist at all. Run from a real terminal app (Terminal, iTerm)
  rather than an embedded IDE shell, and grant it Bluetooth under System Settings →
  Privacy & Security → Bluetooth. If it still aborts, run the CLI through a small app
  bundle carrying the key — copy and amend
  `$(brew --prefix)/Frameworks/Python.framework/Versions/<ver>/Resources/Python.app`.
* **`ble scan` finds nothing**: verify BLE permissions and adapter state, and try a
  longer `--timeout`. A second attempt often succeeds.
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

**There is none.** The CLI makes no network call except the ones a command explicitly
needs: the Hubble Cloud API for the commands that use credentials (`org`, `metrics`,
`doctor`, `validate-credentials`, `ble validate` and `ble scan --ingest`); `localhost`
for the satellite receiver container; and Docker pulling that container image from
`ghcr.io` on first `sat` use. Nothing is reported anywhere about how you use it.

If that ever changes, it would have to be opt-in and off by default; carry nothing
sensitive (no tokens, org or device IDs, keys, payloads, coordinates, hostnames or
paths — command name, exit status and version is the ceiling); list every field sent
in this file; be killable by both a flag and an environment variable; never sit on a
command's critical path; and be covered by a test asserting the payload holds no
credential and no device identifier.


## Releases & versioning

Follows **SemVer**. Pushing a `vX.Y.Z` tag triggers a GitHub Actions workflow that
runs tests, builds the package, creates a GitHub Release, and publishes to PyPI via
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — no API tokens are
stored in the repo. The `pypi` environment requires manual approval in the
[Actions UI](https://github.com/HubbleNetwork/pyhubblenetwork/actions).

To cut a release, use the `/release` skill: it bumps `pyproject.toml`, generates
notes into `release-notes.md` from the conventional-commit log, commits, tags, and
pushes.
