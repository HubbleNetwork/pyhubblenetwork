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
hubblenetwork ready scan
hubblenetwork org list-devices
```

## Architecture

### Package Structure
The SDK uses a src layout with the main package at `src/hubblenetwork/`. Public API is exposed through `__init__.py` - import from the package top-level.

### Core Modules

- **`org.py`** - `Organization` class: credential-scoped operations (register devices, retrieve packets, list devices). Automatically resolves environment (PROD/TESTING) from credentials.

- **`cloud.py`** - Low-level HTTP client for Hubble Cloud API. Contains `Credentials`, `Environment` dataclasses and all REST endpoint functions. Uses `httpx` for HTTP requests.

- **`ble.py`** - BLE scanning for beacon packets (UUID 0xFCA6). Uses `bleak` library. Provides both sync (`scan()`) and async (`scan_async()`) variants.

- **`ready.py`** - Hubble Ready device provisioning (UUID 0xFCA7). Handles GATT connections, characteristic reads/writes, and the full provisioning flow (register with backend, write key/config/time).

- **`crypto.py`** - Local packet decryption. Implements AES-CTR decryption with CMAC-based key derivation (SP800_108_Counter KDF). Supports both AES-256-CTR and AES-128-CTR.

- **`packets.py`** - Data classes: `Location`, `EncryptedPacket`, `DecryptedPacket`.

- **`device.py`** - `Device` dataclass representing a registered device.

- **`errors.py`** - Exception hierarchy. Base `HubbleError` with specialized errors for backend, network, validation, BLE scanning, and decryption failures.

- **`cli.py`** - Click-based CLI. Command groups: `ble` (scan, detect, check-time), `ready` (scan, info, provision), `org` (info, list-devices, get-packets, register-device, set-device-name).

### Key Patterns

- **Sync/Async duality**: BLE and provisioning functions have both sync and async variants. Sync versions use `asyncio.run()` with fallback handling for existing event loops.

- **Environment auto-detection**: `get_env_from_credentials()` tries PROD then TESTING to determine which API the credentials are valid for.

- **Pagination**: Cloud API uses continuation tokens. `Organization.list_devices()` and `retrieve_packets()` handle pagination internally.

- **Encryption modes**: Devices support either AES-256-CTR (32-byte key) or AES-128-CTR (16-byte key). Mode is auto-detected from device during provisioning.

### Environment Variables
- `HUBBLE_ORG_ID` - Organization ID
- `HUBBLE_API_TOKEN` - API token
- For integration tests: `HUBBLE_PROD_ORG_ID`, `HUBBLE_PROD_API_TOKEN`, `HUBBLE_TESTING_ORG_ID`, `HUBBLE_TESTING_API_TOKEN`

### Test Markers
- `@pytest.mark.integration` - Tests requiring real API credentials
- `@pytest.mark.ble` - Tests requiring BLE hardware
