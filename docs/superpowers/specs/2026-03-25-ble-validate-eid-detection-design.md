# BLE Validate: EID Type Detection Design

**Date:** 2026-03-25
**Feature:** Extend `ble validate` to detect and report whether a device uses epoch-based or counter-based EID encryption.

---

## Background

Hubble devices support two EID (Ephemeral ID) counter modes:

- **`EPOCH_TIME`**: The `time_counter` is days since Unix epoch (~20,000 today). `decrypt()` searches a window of ±2 days around today.
- **`DEVICE_UPTIME`**: The `time_counter` is an uptime counter cycling through a pool of size N (valid sizes: 16, 32, 64, 128, 256, 512, 1024). `decrypt()` searches 0 to N-1.

These counter ranges are disjoint (epoch values ~20,000+; pool values 0–1023), making cryptographic detection reliable.

`decrypt()` in `crypto.py` already supports both modes via the `eid_pool_size` parameter. No changes to `crypto.py` are needed.

---

## Goal

Extend Step 6 of `ble validate` to:
1. Try both epoch-based and counter-based decryption on the scanned packets
2. Echo which EID type was detected
3. Note if both resolve (ambiguous)
4. Continue to ingestion in all non-error cases

---

## Scope

Changes confined to `src/hubblenetwork/cli.py` and `tests/test_ble_validate.py`.

`List` and `Optional` are already imported in `cli.py`. `EncryptedPacket` is **not** currently imported; it must be added: change `from hubblenetwork import Device, DecryptedPacket` to `from hubblenetwork import Device, DecryptedPacket, EncryptedPacket`.

---

## Design

### New CLI Option

Add `--pool-size INTEGER` to `ble validate` (default: 1024). The option is a plain `int` — **not** `click.Choice` — which is intentional: all `ble validate` input checks live in Step 1 to produce uniform `[ERROR]`-styled output (the existing `register-device` command uses `click.Choice` for the same value set, but `ble validate` deliberately keeps a different convention). Default 1024 covers all valid pool sizes since 0–15 is a subset of 0–1023.

Validated in Step 1 against `_VALID_POOL_SIZES = {16, 32, 64, 128, 256, 512, 1024}`:

```
Invalid --pool-size value. Must be one of: 16, 32, 64, 128, 256, 512, 1024.
```

### New Helper: `_detect_eid_type`

```python
def _detect_eid_type(
    key: bytes,
    pkts: List[EncryptedPacket],
    pool_size: int,
) -> tuple[Optional[EncryptedPacket], Optional[str], bool]:
```

**Returns:** `(pkt_to_ingest, eid_label, is_ambiguous)`

- `pkt_to_ingest`: the `EncryptedPacket` to use for ingestion (epoch preferred), or `None` if neither resolved
- `eid_label`: `"EPOCH_TIME"`, `"DEVICE_UPTIME"`, `"AMBIGUOUS"`, or `None` (when neither resolves)
- `is_ambiguous`: `True` if both modes resolved

**`days` constraint:** Always calls `decrypt()` with its default `days=2`. `crypto.py:83` raises `ValueError` if `eid_pool_size is not None and days != 2`; using the default avoids this. No `--days` option is added to `ble validate`.

**Logic:**
1. Initialise `epoch_pkt = None`, `counter_pkt = None`
2. For each `pkt` in `pkts`:
   a. If `epoch_pkt` is still `None`, call `decrypt(key, pkt)` — store result in `epoch_pkt` if non-None
   b. If `counter_pkt` is still `None`, call `decrypt(key, pkt, eid_pool_size=pool_size)` — store result in `counter_pkt` if non-None
   c. If both are now non-None, break (early exit)
3. Iteration continues until both are found (early stop) or the entire packet list is exhausted
4. Return based on which results are non-None (see Data Flow table)

When ambiguous, `epoch_pkt` is returned as `pkt_to_ingest`.

`_detect_eid_type` calls `decrypt` via the name `decrypt` as imported into `cli.py` — the same name patched by existing tests (`patch("hubblenetwork.cli.decrypt")`).

### Step 6 Changes in `ble_validate`

Replace the current decryption loop with a call to `_detect_eid_type`. After printing `[SUCCESS]`, echo the EID type on a new indented line.

**Epoch-based:**
```
[INFO] Validating encryption of received packets... [SUCCESS]
       EID type: EPOCH_TIME (day counter=20172)
```
The counter value is `DecryptedPacket.counter` from the epoch result.

**Counter-based:**
```
[INFO] Validating encryption of received packets... [SUCCESS]
       EID type: DEVICE_UPTIME (counter=42)
```
The counter value is the winning pool index from `DecryptedPacket.counter`. The `--pool-size` search bound is not echoed (it is not an intrinsic device property).

**Ambiguous (no counter shown):**
```
[INFO] Validating encryption of received packets... [SUCCESS]
       EID type: AMBIGUOUS (resolved with both EPOCH_TIME and DEVICE_UPTIME)
       NOTE: Multiple devices may be in BLE range with different configs,
             or a very unlikely cryptographic coincidence. Check your device config.
```

**Neither (error, unchanged):**
```
[INFO] Validating encryption of received packets... [ERROR]
Unable to decrypt packet with given device key.
...
```

---

## Data Flow

```
pkts (List[EncryptedPacket] from BLE scan)
    │
    ▼
_detect_eid_type(key, pkts, pool_size)
    ├── for each pkt: decrypt(key, pkt)                          → epoch_pkt
    └── for each pkt: decrypt(key, pkt, eid_pool_size=pool_size) → counter_pkt
    │   (stops early when both non-None; otherwise exhausts pkts)
    │
    ├── epoch only   → (epoch_pkt,   "EPOCH_TIME",    False)
    ├── counter only → (counter_pkt, "DEVICE_UPTIME", False)
    ├── both         → (epoch_pkt,   "AMBIGUOUS",     True)
    └── neither      → (None, None, False) → Step 6 calls _validate_error
```

---

## Input Validation (Step 1)

`--pool-size` checked against `_VALID_POOL_SIZES`. Error message: `Invalid --pool-size value. Must be one of: 16, 32, 64, 128, 256, 512, 1024.`

---

## Error Handling

| Scenario | Behaviour |
|---|---|
| Neither EID mode resolves | Existing error path, message unchanged |
| Invalid `--pool-size` | Step 1 validation error listing valid values |
| Ambiguous detection | `[SUCCESS]` with `AMBIGUOUS` note; proceeds to ingestion using epoch result |

---

## Testing

### Existing test: `test_decryption_failure_error`

This test patches `hubblenetwork.cli.decrypt` with `return_value = None`. Under the new implementation, `_detect_eid_type` calls `decrypt` directly (same module-level name), so the patch target is unchanged. `return_value = None` makes both the epoch call and the counter call return `None`, causing `_detect_eid_type` to return `(None, None, False)`, which hits the existing error path. **This test should pass without modification; verify it still passes.**

### New unit tests for `_detect_eid_type`

**Mock strategy:** Use a `side_effect` callable that inspects `kwargs`: return a mock `DecryptedPacket` when `eid_pool_size` is absent (epoch call) or present (counter call) as required by the test, and `None` otherwise. The mock applies regardless of which `pkt` is passed.

| Test | `side_effect` returns | Expected return |
|---|---|---|
| Epoch only | mock result when `eid_pool_size` absent; `None` when present | `(epoch_pkt, "EPOCH_TIME", False)` |
| Counter only | `None` when `eid_pool_size` absent; mock result when present | `(counter_pkt, "DEVICE_UPTIME", False)` |
| Both (ambiguous) | mock result for both signatures | `(epoch_pkt, "AMBIGUOUS", True)` |
| Neither | `None` for all calls (`return_value = None`) | `(None, None, False)` |
| Stops early | mock result for both signatures on any pkt; `pkts = [pkt0, pkt1]` | `(pkt0, "AMBIGUOUS", True)` and `decrypt.call_count == 2` |

For the "Stops early" test: the side_effect returns a non-None result for any call, regardless of packet identity. On `pkt0`, the epoch call (call 1) succeeds and the counter call (call 2) succeeds — both `epoch_pkt` and `counter_pkt` are set, so the loop exits. `pkt1` is never processed. `call_count == 2` (not 4) confirms early exit.

### New integration tests for `ble validate` CLI

| Test | Mock setup | Expected output |
|---|---|---|
| Epoch EID detected | `decrypt` side_effect: mock `DecryptedPacket` when `eid_pool_size` absent, `None` when present | `"EID type: EPOCH_TIME"` in output |
| Counter EID detected | `decrypt` side_effect: `None` when `eid_pool_size` absent, mock `DecryptedPacket` when present | `"EID type: DEVICE_UPTIME"` in output |
| Invalid `--pool-size=7` | — | exit code != 0, `"Invalid --pool-size"` in output |

---

## Files Changed

| File | Change |
|---|---|
| `src/hubblenetwork/cli.py` | Add `EncryptedPacket` to imports; add `--pool-size` option; add `_detect_eid_type` helper; update Step 1 validation; update Step 6 |
| `tests/test_ble_validate.py` | Verify `test_decryption_failure_error` passes; add unit tests for `_detect_eid_type`; add CLI integration tests |
