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
from hubblenetwork import ble, Organization, Credentials

org = Organization(Credentials(org_id="org_123", api_token="sk_XXX"))
pkts = ble.scan(timeout=5.0)
if len(pkts) > 0:
    org.ingest_packet(pkts[0])
else:
    print("No packet seen within timeout")
```

### Manage devices and query packets

```python
from hubblenetwork import Organization, Credentials

org = Organization(Credentials(org_id="org_123", api_token="sk_XXX"))

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

## CLI usage (optional)

If installed, the `hubblenetwork` command is available:

```bash
hubblenetwork --help
hubblenetwork ble scan
```

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
    ble, cloud,
    Organization, Device,
    EncryptedPacket, DecryptedPacket, Location,
)
```

Key objects & functions:

* `Organization` provides credentials for performing cloud actions (e.g. registering devices, retrieving decrypted packets, retrieving devices, etc.)
* `EncryptedPacket` a packet that has not been decrypted (can be decrypted locally given a key or ingested to the backend)
* `DecryptedPacket` a packet that has been successfully decrypted either locally or by the backend.
* `Location` data about where a packet was seen.
* `ble.scan` function for locally scanning for devices with BLE.

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


## Releases & versioning

* Follows **SemVer** (MAJOR.MINOR.PATCH).
* Tagged releases (e.g., `v0.1.0`) publish wheels/sdists to PyPI.
* Release process: (add short steps for how to cut a release—tagging, CI release job, PyPI publish credentials).
