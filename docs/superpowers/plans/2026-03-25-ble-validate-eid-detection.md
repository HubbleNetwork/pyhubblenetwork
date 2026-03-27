# BLE Validate EID Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `ble validate` to detect whether a device uses epoch-based (`EPOCH_TIME`) or counter-based (`DEVICE_UPTIME`) EID encryption, echo the result, and note if ambiguous.

**Architecture:** Add a `_detect_eid_type` helper to `cli.py` that tries both decryption modes on the scanned BLE packets and returns the result. Step 6 of `ble_validate` is replaced with a call to this helper. A new `--pool-size` CLI option (default 1024) controls the counter-based search range and is validated in Step 1.

**Tech Stack:** Python, Click, existing `decrypt()` from `hubblenetwork.crypto` (already supports both modes via `eid_pool_size` parameter).

**Spec:** `docs/superpowers/specs/2026-03-25-ble-validate-eid-detection-design.md`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `src/hubblenetwork/cli.py` | Modify | Add import, helper, CLI option, Step 1 validation, Step 6 replacement |
| `tests/test_ble_validate.py` | Modify | Add unit tests for helper, CLI integration tests for new option and output |

---

## Background: How `decrypt()` works

`decrypt(key, pkt)` — epoch mode: searches `time_counter` values ±2 days around today (~20,000). Returns `DecryptedPacket` on success, `None` on failure. `DecryptedPacket.counter` holds the winning `time_counter`.

`decrypt(key, pkt, eid_pool_size=N)` — counter mode: searches `time_counter` values 0 to N-1. Same return contract.

**Critical:** `crypto.py:83` raises `ValueError` if `eid_pool_size is not None and days != 2`. Always call `decrypt()` with default `days=2` (the default).

Epoch counters (~20,000+) and counter-mode counters (0–1023) are disjoint, so detection is reliable.

---

## Task 1: Add `EncryptedPacket` to imports

**Files:**
- Modify: `src/hubblenetwork/cli.py:19`

`EncryptedPacket` is in the top-level `hubblenetwork` package (`__init__.py` re-exports it from `packets.py`). It is not currently imported in `cli.py` but is needed for the new helper's type annotation.

- [ ] **Step 1: Update the import line**

In `src/hubblenetwork/cli.py`, change line 19:
```python
# Before
from hubblenetwork import Device, DecryptedPacket

# After
from hubblenetwork import Device, DecryptedPacket, EncryptedPacket
```

- [ ] **Step 2: Verify no import errors**

Run: `python -c "from hubblenetwork.cli import cli"`
Expected: no output (clean import)

- [ ] **Step 3: Commit**

```bash
git add src/hubblenetwork/cli.py
git commit -s -m "chore(cli): import EncryptedPacket for eid detection helper"
```

---

## Task 2: Test and implement `_detect_eid_type` helper

**Files:**
- Modify: `src/hubblenetwork/cli.py` — add helper after `_get_pkt_from_be_with_timestamp` (around line 62), before `_format_payload`
- Test: `tests/test_ble_validate.py` — add `TestDetectEidType` class

The helper returns a 4-tuple `(enc_pkt, dec_pkt, eid_label, is_ambiguous)`:
- `enc_pkt`: `EncryptedPacket` to ingest (epoch preferred), or `None`
- `dec_pkt`: corresponding `DecryptedPacket` (for counter value), or `None`
- `eid_label`: `"EPOCH_TIME"`, `"DEVICE_UPTIME"`, `"AMBIGUOUS"`, or `None`
- `is_ambiguous`: `True` if both modes resolved

The 4-tuple avoids a redundant `decrypt()` call in Step 6 when echoing the counter.

**Mock strategy throughout:** Use a `side_effect` callable that inspects `kwargs`. `decrypt(key, pkt)` is the epoch call (no `eid_pool_size` kwarg); `decrypt(key, pkt, eid_pool_size=N)` is the counter call (`eid_pool_size` in kwargs). The helper is patched at `hubblenetwork.cli.decrypt` — the same module-level name used everywhere.

- [ ] **Step 1: Write the failing tests**

Add this class to `tests/test_ble_validate.py` (also add `_detect_eid_type` to the import from `hubblenetwork.cli`):

```python
from hubblenetwork.cli import (
    _validate_info,
    _validate_success,
    _validate_error,
    _detect_eid_type,
    cli,
)
```

```python
class TestDetectEidType:
    """Unit tests for the _detect_eid_type helper."""

    def test_epoch_only(self):
        pkt = MagicMock()
        mock_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return None if "eid_pool_size" in kwargs else mock_dec

        with patch("hubblenetwork.cli.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt], pool_size=1024)

        assert enc is pkt
        assert dec is mock_dec
        assert label == "EPOCH_TIME"
        assert ambiguous is False

    def test_counter_only(self):
        pkt = MagicMock()
        mock_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return mock_dec if "eid_pool_size" in kwargs else None

        with patch("hubblenetwork.cli.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt], pool_size=1024)

        assert enc is pkt
        assert dec is mock_dec
        assert label == "DEVICE_UPTIME"
        assert ambiguous is False

    def test_ambiguous(self):
        pkt = MagicMock()
        epoch_dec = MagicMock()
        counter_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return counter_dec if "eid_pool_size" in kwargs else epoch_dec

        with patch("hubblenetwork.cli.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt], pool_size=1024)

        assert enc is pkt
        assert dec is epoch_dec  # epoch preferred
        assert label == "AMBIGUOUS"
        assert ambiguous is True

    def test_neither(self):
        pkt = MagicMock()

        with patch("hubblenetwork.cli.decrypt", return_value=None):
            enc, dec, label, ambiguous = _detect_eid_type(b"k" * 16, [pkt], pool_size=1024)

        assert enc is None
        assert dec is None
        assert label is None
        assert ambiguous is False

    def test_stops_early_when_both_found(self):
        """Helper stops after pkts[0] resolves both modes; pkts[1] is never processed."""
        pkt0 = MagicMock()
        pkt1 = MagicMock()

        with patch("hubblenetwork.cli.decrypt", return_value=MagicMock()) as mock_decrypt:
            enc, dec, label, ambiguous = _detect_eid_type(
                b"k" * 16, [pkt0, pkt1], pool_size=1024
            )

        # Both modes resolved on pkt0: 1 epoch call + 1 counter call = 2 total
        assert mock_decrypt.call_count == 2
        assert enc is pkt0
        assert label == "AMBIGUOUS"
        assert ambiguous is True
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_ble_validate.py::TestDetectEidType -v`
Expected: `ImportError` or `NameError` (function does not exist yet)

- [ ] **Step 3: Implement `_detect_eid_type`**

Add after `_get_pkt_from_be_with_timestamp` in `src/hubblenetwork/cli.py` (before `_format_payload`):

```python
def _detect_eid_type(
    key: bytes,
    pkts: List[EncryptedPacket],
    pool_size: int,
) -> tuple[Optional[EncryptedPacket], Optional[DecryptedPacket], Optional[str], bool]:
    epoch_pkt = None
    epoch_dec = None
    counter_pkt = None
    counter_dec = None
    for pkt in pkts:
        if epoch_pkt is None:
            result = decrypt(key, pkt)
            if result:
                epoch_pkt = pkt
                epoch_dec = result
        if counter_pkt is None:
            result = decrypt(key, pkt, eid_pool_size=pool_size)
            if result:
                counter_pkt = pkt
                counter_dec = result
        if epoch_pkt is not None and counter_pkt is not None:
            break
    if epoch_pkt and counter_pkt:
        return (epoch_pkt, epoch_dec, "AMBIGUOUS", True)
    if epoch_pkt:
        return (epoch_pkt, epoch_dec, "EPOCH_TIME", False)
    if counter_pkt:
        return (counter_pkt, counter_dec, "DEVICE_UPTIME", False)
    return (None, None, None, False)
```

- [ ] **Step 4: Run tests — confirm they pass**

Run: `pytest tests/test_ble_validate.py::TestDetectEidType -v`
Expected: 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_ble_validate.py
git commit -s -m "feat(cli): add _detect_eid_type helper for EID mode detection"
```

---

## Task 3: Test and implement `--pool-size` option and Step 1 validation

**Files:**
- Modify: `src/hubblenetwork/cli.py` — add `--pool-size` to `ble validate` decorator and Step 1 validation block
- Test: `tests/test_ble_validate.py` — add test to `TestBleValidateInputs`

`_VALID_POOL_SIZES` is already imported from `hubblenetwork.org` at the top of `cli.py` (line 21).

- [ ] **Step 1: Write the failing test**

Add to `TestBleValidateInputs` in `tests/test_ble_validate.py`:

```python
def test_rejects_invalid_pool_size(self):
    runner = CliRunner()
    key = base64.b64encode(b"a" * 16).decode()
    result = runner.invoke(cli, [
        "ble", "validate",
        "--key", key,
        "--device-id", str(uuid.uuid4()),
        "--pool-size", "7",
    ])
    assert result.exit_code != 0
    assert "Invalid --pool-size" in result.output
```

- [ ] **Step 2: Run test — confirm it fails**

Run: `pytest tests/test_ble_validate.py::TestBleValidateInputs::test_rejects_invalid_pool_size -v`
Expected: FAIL — `--pool-size` option does not exist yet, Click error message won't match

- [ ] **Step 3: Add `--pool-size` option to the command decorator**

In `src/hubblenetwork/cli.py`, find the `@ble.command("validate")` block (around line 1021). Add the new option after the `--timeout` option, before `def ble_validate(...)`:

```python
@click.option(
    "--pool-size",
    type=int,
    default=1024,
    show_default=True,
    help="Pool size for counter-based EID detection (default covers all valid pool sizes).",
)
```

Update the function signature to accept `pool_size: int`:
```python
def ble_validate(key: str, device_id: str, org_id: str, token: str, timeout: int, pool_size: int) -> None:
```

- [ ] **Step 4: Add `--pool-size` validation to Step 1**

In the Step 1 block of `ble_validate` (after the UUID validation, before `_validate_success()`), add:

```python
if pool_size not in _VALID_POOL_SIZES:
    _validate_error(
        f"Invalid --pool-size value. Must be one of: "
        f"{', '.join(str(s) for s in sorted(_VALID_POOL_SIZES))}."
    )
```

- [ ] **Step 5: Run test — confirm it passes**

Run: `pytest tests/test_ble_validate.py::TestBleValidateInputs -v`
Expected: all 4 tests PASS (3 existing + 1 new)

- [ ] **Step 6: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_ble_validate.py
git commit -s -m "feat(cli): add --pool-size option and Step 1 validation to ble validate"
```

---

## Task 4: Test and implement Step 6 EID echo

**Files:**
- Modify: `src/hubblenetwork/cli.py` — replace Step 6 decryption loop with `_detect_eid_type` call + EID echo
- Test: `tests/test_ble_validate.py` — add `TestBleValidateEidOutput` class; verify existing `test_decryption_failure_error` still passes

### About the existing `test_decryption_failure_error` test

This test patches `hubblenetwork.cli.decrypt` with `return_value=None`. Under the new implementation, `_detect_eid_type` calls `decrypt` via the same module-level name. `return_value=None` makes both the epoch call and the counter call return `None`, so `_detect_eid_type` returns `(None, None, None, False)`. Step 6 then checks `if not pkt_to_ingest` → calls `_validate_error`. The test should still pass without modification.

### Mock strategy for integration tests

These tests need to get through Steps 1–6 successfully to see the EID echo. Use:
- `patch("hubblenetwork.cli.Organization")` — mock org with `list_devices` returning the device
- `patch("hubblenetwork.cli.ble_mod")` — mock scan returning one fake packet
- `patch("hubblenetwork.cli.decrypt", side_effect=...)` — control epoch/counter results
- `patch("hubblenetwork.cli._get_pkt_from_be_with_timestamp", return_value=mock_backend_pkt)` — skip the polling loop cleanly

The `decrypt` side_effect for epoch-only: return `MagicMock(counter=20172)` when `eid_pool_size` is absent; `None` when present. For counter-only: the reverse.

- [ ] **Step 1: Write the failing integration tests**

Add this class to `tests/test_ble_validate.py`:

```python
class TestBleValidateEidOutput:
    """Integration tests verifying EID type is echoed in Step 6 output."""

    def test_epoch_eid_reported(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())

        def decrypt_side_effect(*args, **kwargs):
            return MagicMock(counter=20172) if "eid_pool_size" not in kwargs else None

        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.cli.decrypt", side_effect=decrypt_side_effect), \
             patch("hubblenetwork.cli._get_pkt_from_be_with_timestamp",
                   return_value=MagicMock(device_name="n", payload=b"p", sequence=1)):
            mock_org = mock_org_cls.return_value
            mock_org.list_devices.return_value = [MagicMock(id=device_id)]
            mock_ble.scan.return_value = [MagicMock()]
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])

        assert "EID type: EPOCH_TIME" in result.output
        assert "20172" in result.output

    def test_counter_eid_reported(self):
        runner = CliRunner()
        key = base64.b64encode(b"a" * 16).decode()
        device_id = str(uuid.uuid4())

        def decrypt_side_effect(*args, **kwargs):
            return MagicMock(counter=42) if "eid_pool_size" in kwargs else None

        with patch("hubblenetwork.cli.Organization") as mock_org_cls, \
             patch("hubblenetwork.cli.ble_mod") as mock_ble, \
             patch("hubblenetwork.cli.decrypt", side_effect=decrypt_side_effect), \
             patch("hubblenetwork.cli._get_pkt_from_be_with_timestamp",
                   return_value=MagicMock(device_name="n", payload=b"p", sequence=1)):
            mock_org = mock_org_cls.return_value
            mock_org.list_devices.return_value = [MagicMock(id=device_id)]
            mock_ble.scan.return_value = [MagicMock()]
            result = runner.invoke(cli, [
                "ble", "validate",
                "--key", key,
                "--device-id", device_id,
                "--org-id", "fake-org",
                "--token", "fake-token",
            ])

        assert "EID type: DEVICE_UPTIME" in result.output
        assert "42" in result.output
```

- [ ] **Step 2: Run tests — confirm they fail**

Run: `pytest tests/test_ble_validate.py::TestBleValidateEidOutput -v`
Expected: FAIL — Step 6 still uses the old loop, no EID type in output

- [ ] **Step 3: Replace Step 6 in `ble_validate`**

In `src/hubblenetwork/cli.py`, replace the current Step 6 block (lines ~1145–1161):

```python
# Before (lines ~1145-1161)
    # Step 6: Validate encryption
    _validate_info("Validating encryption of received packets")
    pkt_to_ingest = None
    for pkt in pkts:
        if decrypt(decoded_key, pkt):
            pkt_to_ingest = pkt
            break
    if not pkt_to_ingest:
        _validate_error(
            'Unable to decrypt packet with given device key.'
            '\n\nDebug tips:'
            '\n 1. Ensure you entered the key correctly when running this script.'
            '\n 2. Check that your device is provisioned with this same key.'
            '\n 3. Check that your device-level encryption is working.'
            '\n\nIf these do not resolve your issue please contact support@hubble.com.'
        )
    _validate_success()
```

```python
# After
    # Step 6: Validate encryption and detect EID type
    _validate_info("Validating encryption of received packets")
    pkt_to_ingest, dec_result, eid_label, _ = _detect_eid_type(decoded_key, pkts, pool_size)
    if not pkt_to_ingest:
        _validate_error(
            'Unable to decrypt packet with given device key.'
            '\n\nDebug tips:'
            '\n 1. Ensure you entered the key correctly when running this script.'
            '\n 2. Check that your device is provisioned with this same key.'
            '\n 3. Check that your device-level encryption is working.'
            '\n\nIf these do not resolve your issue please contact support@hubble.com.'
        )
    _validate_success()
    if eid_label == "EPOCH_TIME":
        click.echo(f"       EID type: EPOCH_TIME (day counter={dec_result.counter})")
    elif eid_label == "DEVICE_UPTIME":
        click.echo(f"       EID type: DEVICE_UPTIME (counter={dec_result.counter})")
    else:
        click.echo("       EID type: AMBIGUOUS (resolved with both EPOCH_TIME and DEVICE_UPTIME)")
        click.secho(
            "       NOTE: Multiple devices may be in BLE range with different configs,\n"
            "             or a very unlikely cryptographic coincidence. "
            "Check your device config.",
            bold=True,
        )
```

- [ ] **Step 4: Run new tests — confirm they pass**

Run: `pytest tests/test_ble_validate.py::TestBleValidateEidOutput -v`
Expected: 2 tests PASS

- [ ] **Step 5: Verify existing tests still pass (including `test_decryption_failure_error`)**

Run: `pytest tests/test_ble_validate.py -v`
Expected: all tests PASS (existing + new)

If `test_decryption_failure_error` fails: the mock `return_value=None` should already work since `_detect_eid_type` calls `decrypt` under the same patched name. If it still fails, inspect the error and fix the test mock — it may need to explicitly set `mock_decrypt.return_value = None` (which it already does).

- [ ] **Step 6: Run linter**

Run: `ruff check src/hubblenetwork/cli.py`
Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_ble_validate.py
git commit -s -m "feat(cli): detect and echo EID type in ble validate step 6"
```
