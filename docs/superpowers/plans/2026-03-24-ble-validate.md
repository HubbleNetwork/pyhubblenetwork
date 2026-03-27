# `ble validate` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `ble validate` command that performs end-to-end validation of a Hubble device (inputs, credentials, registration, BLE scan, encryption, backend ingestion/retrieval).

**Architecture:** Single command function added to the existing `ble` Click group in `cli.py`. Four small helper functions at module level. Reuses existing SDK primitives and credential resolution.

**Tech Stack:** Python, Click CLI framework, existing hubblenetwork SDK

**Spec:** `docs/superpowers/specs/2026-03-23-ble-validate-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/hubblenetwork/cli.py` | Modify | Add helper functions and `ble validate` command |
| `tests/test_ble_validate.py` | Create | Unit tests for input validation and helper functions |

---

### Task 1: Create branch

**Files:** None (git operation)

- [ ] **Step 1: Create and switch to new branch**

```bash
git checkout -b feat/ble-validate
```

- [ ] **Step 2: Verify branch**

Run: `git branch --show-current`
Expected: `feat/ble-validate`

---

### Task 2: Add output helper functions

**Files:**
- Modify: `src/hubblenetwork/cli.py` (insert after line ~33, before `_format_payload`)
- Test: `tests/test_ble_validate.py`

- [ ] **Step 1: Write tests for helper functions**

Create `tests/test_ble_validate.py`:

```python
"""Tests for ble validate command helpers."""
import pytest
from unittest.mock import patch
from click.testing import CliRunner

from hubblenetwork.cli import (
    _validate_info,
    _validate_success,
    _validate_error,
)


class TestValidateHelpers:
    def test_validate_info_prints_cyan_info_tag(self, capsys):
        _validate_info("Testing something")
        captured = capsys.readouterr()
        assert "Testing something..." in captured.out

    def test_validate_success_prints_green_success_tag(self, capsys):
        _validate_success()
        captured = capsys.readouterr()
        assert "SUCCESS" in captured.out

    def test_validate_error_prints_and_exits(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            _validate_error("Something broke")
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "ERROR" in captured.out
        assert "Something broke" in captured.out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_ble_validate.py -v`
Expected: FAIL — `_validate_info` cannot be imported

- [ ] **Step 3: Implement helper functions**

Add these to `cli.py` after the logger setup (before `_format_payload` at line 35). Also add the `_get_pkt_from_be_with_timestamp` helper:

```python
def _validate_info(msg):
    """Print a cyan [INFO] tag followed by the step description."""
    click.secho("[INFO] ", fg="cyan", bold=True, nl=False)
    click.echo(msg + "... ", nl=False)


def _validate_success():
    """Print a green [SUCCESS] tag."""
    click.secho("[SUCCESS]", fg="green", bold=True)


def _validate_error(msg):
    """Print a red [ERROR] tag with details, then exit."""
    click.secho("[ERROR]", fg="red", bold=True)
    click.secho(f"\n{msg}", bold=True)
    sys.exit(1)


def _get_pkt_from_be_with_timestamp(org, device, timestamp):
    """Search backend packets for one matching the given timestamp."""
    backend_pkts = org.retrieve_packets(device, days=1)
    for p in backend_pkts:
        if p.timestamp == timestamp:
            return p
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_ble_validate.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_ble_validate.py
git commit -m "feat(cli): add validate output helper functions"
```

---

### Task 3: Add `ble validate` command skeleton with input validation

**Files:**
- Modify: `src/hubblenetwork/cli.py` (add command after `ble_check_time`, before the `ready` group)
- Modify: `tests/test_ble_validate.py`

The `ble_check_time` function ends around line 990, and the `ready` group starts at line 995. The new command goes between them.

- [ ] **Step 1: Write tests for input validation**

Add to `tests/test_ble_validate.py`:

```python
import uuid
import base64
from hubblenetwork.cli import cli


class TestBleValidateInputs:
    """Test input validation (step 1 of the validate flow)."""

    def test_rejects_invalid_base64_key(self):
        runner = CliRunner()
        result = runner.invoke(cli, [
            "ble", "validate",
            "--key", "not-valid-base64!!!",
            "--device-id", str(uuid.uuid4()),
        ])
        assert result.exit_code != 0
        assert "Incorrectly formatted device key" in result.output

    def test_rejects_invalid_uuid(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        result = runner.invoke(cli, [
            "ble", "validate",
            "--key", key,
            "--device-id", "not-a-uuid",
        ])
        assert result.exit_code != 0
        assert "Device UUID formatted incorrectly" in result.output

    def test_accepts_valid_inputs_then_fails_on_credentials(self):
        """Valid key+uuid should pass step 1, then fail at step 2 (no creds)."""
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        result = runner.invoke(cli, [
            "ble", "validate",
            "--key", key,
            "--device-id", device_id,
        ])
        # Should pass input validation (shows SUCCESS for step 1)
        # then fail on credentials (no env vars set)
        assert "Validating format of inputs" in result.output


class TestBleValidateErrorPaths:
    """Test error handling for validation steps 4-6 using mocks."""

    def test_unregistered_device_error(self):
        """Step 4: RequestError when device is not registered."""
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org = mock_org_cls.return_value
            mock_org.retrieve_packets.side_effect = RequestError("not found")
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "Device ID not found" in result.output

    def test_no_ble_packets_error(self):
        """Step 5: Error when BLE scan returns no packets."""
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble:
            mock_org = mock_org_cls.return_value
            mock_org.retrieve_packets.return_value = []
            mock_ble.scan.return_value = []
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "No Hubble advertisements found" in result.output

    def test_decryption_failure_error(self):
        """Step 6: Error when no packet can be decrypted."""
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())
        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.cli.decrypt") as mock_decrypt:
            mock_org = mock_org_cls.return_value
            mock_org.retrieve_packets.return_value = []
            mock_ble.scan.return_value = [object()]  # one fake packet
            mock_decrypt.return_value = None
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])
        assert result.exit_code != 0
        assert "Unable to decrypt packet" in result.output


class TestGetPktFromBeWithTimestamp:
    def test_returns_matching_packet(self):
        from hubblenetwork.cli import _get_pkt_from_be_with_timestamp
        from unittest.mock import MagicMock

        mock_org = MagicMock()
        mock_device = MagicMock()
        pkt1 = MagicMock(timestamp=100)
        pkt2 = MagicMock(timestamp=200)
        mock_org.retrieve_packets.return_value = [pkt1, pkt2]

        result = _get_pkt_from_be_with_timestamp(mock_org, mock_device, 200)
        assert result is pkt2

    def test_returns_none_when_no_match(self):
        from hubblenetwork.cli import _get_pkt_from_be_with_timestamp
        from unittest.mock import MagicMock

        mock_org = MagicMock()
        mock_device = MagicMock()
        mock_org.retrieve_packets.return_value = [MagicMock(timestamp=100)]

        result = _get_pkt_from_be_with_timestamp(mock_org, mock_device, 999)
        assert result is None
```

Note: The `TestBleValidateErrorPaths` tests need an additional import at the top of the file:
```python
from hubblenetwork.errors import RequestError
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_ble_validate.py::TestBleValidateInputs -v`
Expected: FAIL — no `ble validate` command exists

- [ ] **Step 3: Implement the command**

Add the `ble validate` command to `cli.py`. This needs an import of `RequestError` from `hubblenetwork.errors` at the top of the file (add to existing imports). The command goes after `ble_check_time` and before the `@cli.group()` for `ready`.

Add these imports near the other hubblenetwork imports at the top:
```python
import uuid
from hubblenetwork.errors import RequestError
```

Add the command:

```python
@ble.command("validate")
@click.option(
    "--key",
    "-k",
    type=str,
    required=True,
    show_default=False,
    help="Device key (to test packet encryption)",
)
@click.option(
    "--device-id",
    "-d",
    type=str,
    required=True,
    show_default=False,
    help="Device ID (to test backend)",
)
@click.option(
    "--org-id",
    type=str,
    envvar="HUBBLE_ORG_ID",
    default=None,
    show_default=False,
    help="Organization ID (if not using HUBBLE_ORG_ID env var)",
)
@click.option(
    "--token",
    type=str,
    envvar="HUBBLE_API_TOKEN",
    default=None,
    show_default=False,
    help="Token (if not using HUBBLE_API_TOKEN env var)",
)
@click.option(
    "--timeout",
    "-t",
    type=int,
    default=30,
    show_default=True,
    help="BLE scan timeout in seconds",
)
def ble_validate(key: str, device_id: str, org_id: str, token: str, timeout: int) -> None:
    """
    Validate the operation of a Hubble device, including:

    \b
    - Valid credentials passed in
    - Device registration (must be a registered device)
    - BLE advertisements
    - Advertisement encryption
    - Backend ingestion/retrieval of data

    NOTE: HUBBLE_ORG_ID and HUBBLE_API_TOKEN env vars must be set
    unless --org-id and --token are provided.
    """

    # Step 1: Validate inputs
    _validate_info("Validating format of inputs")
    try:
        decoded_key = base64.b64decode(key)
    except Exception:
        _validate_error(
            'Incorrectly formatted device key passed in. Must be a base 64'
            '\nencoded string such as (fake keys):'
            '\n 16byte key: "q9vH3u2J4aN8Rw1KpZsO+A=="'
            '\n 32byte key: "N4e7xq9X1pQ0sVbY2mT3uA6fH9rK2dW5cG8jL1oQ0vU="'
            '\nNote the "=" characters at the end which must be included.'
        )
    try:
        uuid.UUID(device_id)
    except ValueError:
        _validate_error(
            'Device UUID formatted incorrectly.'
            '\nMust be in standard 8-4-4-4-12 format (removing hyphens accepted).'
            '\nExample UUID: "3f4b2c0c-2d43-4cbe-9c1f-0a4c2d59e2a1"'
            '\n\nIf you are having troubles with your UUID please contact support@hubble.com'
        )
    _validate_success()

    # Step 2: Get credentials
    _validate_info("Getting organization ID and API token")
    try:
        org_id, token = _get_org_and_token(org_id, token)
    except click.ClickException:
        _validate_error("HUBBLE_ORG_ID and/or HUBBLE_API_TOKEN environment variables not set")
    _validate_success()

    # Step 3: Validate org credentials
    _validate_info("Validating organization credentials")
    try:
        org = Organization(
            org_id=org_id,
            api_token=token,
        )
    except InvalidCredentialsError:
        _validate_error("Invalid credentials (Org ID or API token) passed in.")
    _validate_success()

    # Step 4: Validate device registration
    _validate_info("Validating that the given device is registered")
    device = Device(id=device_id)
    try:
        org.retrieve_packets(device)
    except RequestError:
        _validate_error("Device ID not found in backend")
    _validate_success()

    # Step 5: BLE scan
    _validate_info(f"Scanning for Hubble-compatible advertisers (timeout={timeout}s)")
    pkts = ble_mod.scan(timeout=timeout)
    if len(pkts) == 0:
        _validate_error(
            'No Hubble advertisements found.'
            '\n\nNOTE: This may be due to a slow advertising interval and BLE-scanning'
            '\n      optimizations done by your operating system. Try running this'
            '\n      script again if your advertising interval is slow.'
            '\n\nOther debug tips:'
            '\n 1. Ensure your advertising packet is constructed correctly with both'
            '\n    the "Complete List of 16-bit Service UUIDs" advertising type (with'
            '\n    the Hubble UUID) and "Service Data" type included.'
            '\n 2. Ensure your device as advertising at all (if in doubt, try a BLE'
            '\n    scanning app on your phone)'
            '\n\nIf these do not resolve your issue please contact support@hubble.com.'
        )
    _validate_success()

    # Step 6: Validate encryption
    _validate_info("Validating encryption of received packets")
    decrypted_pkt = None
    pkt_to_ingest = None
    for pkt in pkts:
        decrypted_pkt = decrypt(decoded_key, pkt)
        if decrypted_pkt:
            pkt_to_ingest = pkt
            break
    if not decrypted_pkt:
        _validate_error(
            'Unable to decrypt packet with given device key.'
            '\n\nDebug tips:'
            '\n 1. Ensure you entered the key correctly when running this script.'
            '\n 2. Check that your device is provisioned with this same key.'
            '\n 3. Check that your device-level encryption is working.'
            '\n\nIf these do not resolve your issue please contact support@hubble.com.'
        )
    _validate_success()

    # Step 7: Ingest + backend retrieval
    _validate_info("Ingesting packet into the backend")
    try:
        org.ingest_packet(pkt_to_ingest)
    except Exception:
        _validate_error("Unable to ingest packet on the backend (not your fault)")
    _validate_success()

    _validate_info("Checking for packet in the backend")
    timestamp = pkt_to_ingest.timestamp
    backend_pkt = None
    for _ in range(10):
        time.sleep(1)
        backend_pkt = _get_pkt_from_be_with_timestamp(org, device, timestamp)
        if backend_pkt:
            break
    if not backend_pkt:
        _validate_error("Unable to retrieve packet from the backend")
    _validate_success()

    click.secho(f"\n[COMPLETE] All validation steps passed!", fg="green", bold=True)
    click.secho("Packet metadata:")
    click.secho(f'\tname:     "{backend_pkt.device_name}"')
    click.secho(f'\tpayload:  "{backend_pkt.payload}"')
    click.secho(f"\tsequence: {backend_pkt.sequence}")
```

Note: `uuid` and `RequestError` imports are added in the step above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_ble_validate.py -v`
Expected: All tests PASS

- [ ] **Step 5: Run linter**

Run: `ruff check src/hubblenetwork/cli.py`
Expected: No errors (or pre-existing only)

- [ ] **Step 6: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_ble_validate.py
git commit -m "feat(cli): add ble validate command with input validation"
```

---

### Task 4: Verify CLI help and full flow

**Files:** None (verification only)

- [ ] **Step 1: Verify command appears in help**

Run: `hubblenetwork ble --help`
Expected: `validate` listed as a subcommand

- [ ] **Step 2: Verify command help text**

Run: `hubblenetwork ble validate --help`
Expected: Shows all options (--key, --device-id, --org-id, --token, --timeout) with descriptions

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/test_ble_validate.py -v`
Expected: All tests PASS

- [ ] **Step 4: Run linter on entire source**

Run: `ruff check src`
Expected: No new errors

- [ ] **Step 5: Final commit (if any fixups needed)**

```bash
git add src/hubblenetwork/cli.py tests/test_ble_validate.py
git commit -m "chore: fixups from validation"
```
