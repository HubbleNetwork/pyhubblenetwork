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
- [Satellite scanning (PlutoSDR)](#satellite-scanning-plutosdr)
- [Configuration](#configuration)
- [Public API (summary)](#public-api-summary)
- [Development & tests](#development--tests)
- [Troubleshooting](#troubleshooting)
- [Releases & versioning](#releases--versioning)


## Quick links

- [PyPI](https://pypi.org/project/pyhubblenetwork/): `pip install pyhubblenetwork`
- [Hubble official doc site](https://docs.hubble.com/docs/intro)
- [Hubble embedded SDK](https://github.com/HubbleNetwork/sdk)


## Requirements & supported platforms

- Python **3.9+** (3.11/3.12 recommended)
- BLE platform prerequisites (only needed if you use `ble.scan()`):
  - **macOS**: CoreBluetooth; run in a regular user session (GUI).
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

From the repo root (recommended):

```bash
cd python
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

For devices using counter-based EID (DEVICE_UPTIME mode), pass `counter_mode=True`:

```python
maybe_dec = decrypt(dev.key, pkt, counter_mode=True)
```

Counter-mode decryption uses a fixed pool size of 128 (counter values 0–127).

### Receive satellite packets

```python
from hubblenetwork import sat

# sat.scan() manages the Docker container automatically:
# pulls the image, starts the container, polls for packets, and stops on exit.
for pkt in sat.scan(timeout=60.0):
    print(f"device={pkt.device_id}  seq={pkt.seq_num}  rssi={pkt.rssi_dB} dB  payload={pkt.payload.hex()}")
```

Docker must be running before calling `sat.scan()`. The PlutoSDR dongle must be connected.

## CLI usage (optional)

If installed, the `hubblenetwork` command is available:

```bash
hubblenetwork --help
hubblenetwork ble scan
hubblenetwork ble scan --payload-format hex
hubblenetwork ble scan --key "base64key=" --counter-mode   # counter-based EID decryption
hubblenetwork org get-packets --payload-format string
```

### Payload format option

Commands that output packet data (`ble scan`, `ble detect`, `org get-packets`) support the `--payload-format` flag to control how payloads are displayed:

* `base64` (default) — encode payloads as base64
* `hex` — display payloads as hexadecimal
* `string` — decode payloads as UTF-8 text (falls back to `<invalid UTF-8>` if bytes are not valid UTF-8)

This applies to all output formats (tabular, json, csv).

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

# JSON output (one object per line)
hubblenetwork sat scan -o json

# Combine options
hubblenetwork sat scan -o json --timeout 60 -n 20
```

The command automatically:
1. Verifies Docker is available
2. Pulls the latest PlutoSDR image (if not cached)
3. Starts the container in privileged mode so it can access USB
4. Waits for the receiver API to become ready
5. Streams new packets as they arrive (deduplicating by device ID + sequence number)
6. Stops and removes the container on exit or Ctrl+C

### Python API

```python
from hubblenetwork import sat, SatellitePacket

# Generator — yields SatellitePacket as packets arrive
for pkt in sat.scan(timeout=60.0, poll_interval=2.0):
    print(pkt.device_id, pkt.seq_num, pkt.rssi_dB, pkt.payload.hex())

# Or fetch the current packet buffer without managing the container yourself
packets: list[SatellitePacket] = sat.fetch_packets()
```

`SatellitePacket` fields: `device_id`, `seq_num`, `device_type`, `timestamp`, `rssi_dB`, `channel_num`, `freq_offset_hz`, `payload` (bytes).

### Errors

| Exception | Cause |
|-----------|-------|
| `DockerError` | Docker not installed, daemon not running, or container failed to start |
| `SatelliteError` | Container started but receiver API did not become ready in time |

## Configuration

Some functions read defaults from environment variables if not provided explicitly. Suggested variables:

* `HUBBLE_ORG_ID` — default organization id
* `HUBBLE_API_TOKEN` — API token (base64 encoded)

Example:

```bash
export HUBBLE_ORG_ID=org_123
export HUBBLE_API_TOKEN=sk_XXXX
```

You can also pass org ID and API token into API calls.

## Public API (summary)

Import from the package top-level for a stable surface:

```python
from hubblenetwork import (
    ble, cloud, sat,
    Organization, Device, Credentials, Environment,
    EncryptedPacket, DecryptedPacket, SatellitePacket, Location,
    decrypt, InvalidCredentialsError,
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

See code for full details.

## Development & tests

Set up a virtualenv and install dev deps:

```bash
cd python
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
* **Auth errors**: confirm `Organization(org_id, api_token)` or env vars are set; check token scope/expiry.
* **Import errors**: ensure you installed into the Python you’re running (`python -m pip …`). Prefer `pipx` for CLI-only usage.
* **`DockerError: Docker is not available`**: Docker daemon is not running. Start Docker Desktop (macOS/Windows) or `sudo systemctl start docker` (Linux).
* **`DockerError: The ‘docker’ Python package is required`**: run `pip install docker` (it is bundled with `pyhubblenetwork` but may be missing in some environments).
* **`SatelliteError: Satellite receiver API did not become ready`**: the PlutoSDR container started but couldn’t access the hardware. Ensure the ADALM-PLUTO dongle is plugged in before running `sat scan`, and that no other process is using it.
* **`sat scan` hangs pulling the image**: first run fetches `ghcr.io/hubblenetwork/sdr-docker:latest`; this may take a minute on a slow connection. Subsequent runs use the cached image.


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
