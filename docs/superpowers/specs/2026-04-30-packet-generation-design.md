# Hubble Packet Generation — Design

**Status:** Draft
**Date:** 2026-04-30
**Owner:** Paul Buckley

## Summary

Add the ability to generate (encrypt) Hubble BLE advertisement packets locally from a key and a payload. This is the inverse of the existing `decrypt()` / `decrypt_eax()` flow. Generated packets can be ingested to the Hubble Cloud (`--ingest`) and printed in several formats so users can compare a synthetic packet against one observed on hardware.

## Motivation

Today the SDK only consumes encrypted packets (BLE scan → decrypt → render). There's no supported way to produce a well-formed encrypted packet from a key. This makes it hard to:

- Validate end-to-end ingestion paths without real hardware in hand.
- Match a packet captured on the wire against what the spec says it *should* look like for known inputs.
- Seed the cloud with deterministic test data.

This feature provides both an SDK primitive and a CLI command for these workflows.

## Scope

**In scope:**

- AES-CTR (protocol v0) and AES-EAX (protocol v2) packet generation.
- Real EID generation (matches firmware) for both protocols, so backend lookups succeed.
- CLI command (`hubblenetwork ble generate`) wrapping the SDK with formatting and ingest options.
- `--ingest` flag posting via the existing `Organization.ingest_packet`.

**Out of scope (filed as follow-ups):**

- Generating unencrypted protocol v1 packets ("based on a key" doesn't apply).
- Multi-packet generation (`--count N`).
- Fixing the pre-existing bug that BLE-received `AesEaxPacket`s can't be ingested via `Organization.ingest_packet` (the ingest path reads `.payload` and currently expects the full BLE service data; on `AesEaxPacket` `.payload` is the inner ciphertext only). Tracked as a follow-up — this spec works around it by having `encrypt_eax()` return an `EncryptedPacket` carrying the full v2 bytes.
- Adding EID verification to the receive-side `decrypt()` (we now know the algorithm, but verifying isn't required for this feature).

## Design

### High-level architecture

Two new pure functions in `src/hubblenetwork/crypto.py`, exported from `hubblenetwork/__init__.py`. A new `ble generate` Click subcommand in `src/hubblenetwork/cli.py` wraps them with formatting and ingest plumbing.

```
                ┌─────────────────────────────────────┐
                │ CLI: hubblenetwork ble generate     │
                │   parses flags, dispatches by       │
                │   key length, formats output,       │
                │   optionally ingests                │
                └────────────┬────────────────────────┘
                             │
                ┌────────────▼────────────────────────┐
                │ SDK: hubblenetwork.encrypt()        │
                │      hubblenetwork.encrypt_eax()    │
                │   pure functions, return            │
                │   EncryptedPacket with full BLE     │
                │   service-data bytes in .payload    │
                └────────────┬────────────────────────┘
                             │ reuses
                ┌────────────▼────────────────────────┐
                │ Existing helpers in crypto.py:      │
                │   _generate_kdf_key, _get_nonce,    │
                │   _get_encryption_key,              │
                │   _get_auth_tag, _generate_eid      │
                └─────────────────────────────────────┘
```

### SDK API

Both functions are added to `crypto.py` next to their inverses, and re-exported through `hubblenetwork/__init__.py`.

```python
def encrypt(
    key: bytes,
    payload: bytes,
    *,
    time_counter: Optional[int] = None,
    seq_no: Optional[int] = None,
    counter_mode: str = UNIX_TIME,
) -> EncryptedPacket:
    """Generate an AES-CTR (protocol v0) encrypted Hubble BLE packet.

    Args:
        key: 16 or 32 bytes (AES-128 or AES-256).
        payload: plaintext to encrypt. Maximum length is bounded by the BLE
            advertisement frame; the implementation enforces the same ceiling
            firmware uses (see "Open questions").
        time_counter: For UNIX_TIME mode, the UTC day counter
            (`int(time.time()) // 86400`). For DEVICE_UPTIME mode, the
            device's uptime counter index. Defaults to today's UTC day
            (UNIX_TIME) or 0 (DEVICE_UPTIME).
        seq_no: 10-bit sequence number (0..1023). Defaults to a random value.
        counter_mode: "UNIX_TIME" or "DEVICE_UPTIME". Affects only the default
            of `time_counter`; the encryption math is identical.

    Returns:
        EncryptedPacket whose `.payload` field is the full BLE service-data
        byte string (header(2) | EID(4) | auth_tag(4) | ciphertext).

    Raises:
        ValueError: invalid key length, payload too long, seq_no out of range,
            or invalid counter_mode.
    """

def encrypt_eax(
    key: bytes,
    payload: bytes,
    *,
    counter: Optional[int] = None,
    nonce_salt: Optional[bytes] = None,
    period_exponent: int = 0,
) -> EncryptedPacket:
    """Generate an AES-EAX (protocol v2) encrypted Hubble BLE packet.

    Args:
        key: 16 bytes (AES-128).
        payload: 0-9 bytes plaintext to encrypt.
        counter: EID counter index. Effective counter value is
            `counter * 2**period_exponent`. Defaults to 0.
        nonce_salt: 2 random bytes. Defaults to `secrets.token_bytes(2)`.
        period_exponent: 0..15. Period = 2^n seconds. Default 0.

    Returns:
        EncryptedPacket whose `.payload` field is the full BLE service-data
        byte string (header(1) | nonce_salt(2) | EID_le(8) | ciphertext | tag(4)).
        `protocol_version=2`, `eid` and `auth_tag` are populated from the v2 fields.

    Raises:
        ValueError: invalid key length, payload too long, nonce_salt wrong size,
            or period_exponent out of range.
    """
```

**Why both return `EncryptedPacket` (not `AesEaxPacket` for the v2 case):** The existing `Organization.ingest_packet` accepts an `EncryptedPacket` and reads `.payload` as the BLE adv bytes to base64-encode. Returning an `EncryptedPacket` from `encrypt_eax()` lets `--ingest` work without changing the cloud module. The protocol version, EID, and auth_tag are preserved in the dataclass fields so downstream code can still inspect them. (Fixing the broader EAX-ingest gap for BLE-received packets is a separate follow-up.)

### CLI

```
hubblenetwork ble generate
    --key <hex|base64>          required
    --payload <hex|base64|str>  required (with --payload-format)
    --payload-format hex|base64|string  default: hex
    [--counter-mode UNIX_TIME|DEVICE_UPTIME]   CTR-only; default UNIX_TIME
    [--counter N]                              CTR: time_counter override; EAX: counter override
    [--seq-no N]                               CTR-only; 0..1023
    [--nonce-salt <hex>]                       EAX-only; exactly 2 bytes
    [--period-exponent 0..15]                  EAX-only; default 0
    [--ingest]                                 POST to backend (requires HUBBLE_ORG_ID/HUBBLE_API_TOKEN)
    [--format breakdown|hex|json]              default: breakdown
```

Format selection: 32-byte key → AES-CTR; 16-byte key → AES-EAX. Same convention as the receive side and consistent with `_parse_key()`.

Validation rejects flags that don't apply to the chosen format (e.g. `--seq-no` with a 16-byte key, `--nonce-salt` with a 32-byte key). Errors surface as `click.UsageError` so they appear consistently with the existing CLI's error path.

### Data flow

#### `encrypt()` — AES-CTR (v0)

1. Validate `key` length (16 or 32) and `payload` length (≤ MAX_CTR_PAYLOAD; see "Open questions").
2. Resolve defaults:
   - `seq_no` ← random 10-bit if not provided.
   - `time_counter` ← `int(time.time()) // 86400` (UNIX_TIME) or `0` (DEVICE_UPTIME) if not provided.
3. Compute encryption key: `_get_encryption_key(key, time_counter, seq_no, keylen)`.
4. Compute nonce: `_get_nonce(key, time_counter, seq_no, keylen)`.
5. Encrypt: `AES.new(enc_key, AES.MODE_CTR, nonce=nonce).encrypt(payload)` → ciphertext.
6. Compute auth tag: `_get_auth_tag(enc_key, ciphertext)` → 4 bytes.
7. Compute EID via new helper:
   ```python
   def _generate_ctr_eid(key, time_counter, keylen):
       device_key = _generate_kdf_key(key, keylen, "DeviceKey", time_counter)
       return _generate_kdf_key(device_key, 4, "DeviceID", 0)
   ```
   Algorithm matches firmware `hubble_internal_device_id_get` (KBKDF chain with `DeviceKey` then `DeviceID` labels, `seq_no` hardcoded to 0 for EID derivation).
8. Pack header: `(version << 10) | (seq_no & 0x3FF)` as 2 big-endian bytes (version=0).
9. Concatenate: `header(2) | EID(4) | auth_tag(4) | ciphertext`.
10. Return `EncryptedPacket(timestamp=now, location=_FAKE_LOCATION, payload=<service_data>, rssi=0, protocol_version=0, eid=<int>, auth_tag=<bytes>)`.

#### `encrypt_eax()` — AES-EAX (v2)

1. Validate `key` length (must be 16) and `payload` length (≤9). Validate `nonce_salt` (2 bytes) and `period_exponent` (0..15).
2. Resolve defaults: `counter` ← 0 if not provided; `nonce_salt` ← `secrets.token_bytes(2)` if not provided.
3. Compute EID using the **same formula `decrypt_eax` uses** so round-trip is guaranteed: derive `key_0 = _derive_eid_key(key, 0)` once, then `eid_block = AES_ECB(key_0, b"\x00"*11 + period_exponent.to_bytes(1,"big") + (counter * (1 << period_exponent)).to_bytes(4,"big"))`, take first 8 bytes as a big-endian uint64. (The existing `_generate_eid` helper diverges from `decrypt_eax` when `counter * 2**period_exponent ≥ 65536`. Match `decrypt_eax` here.)
4. Build nonce: `(counter * (1 << period_exponent)).to_bytes(4, "big") + nonce_salt`.
5. Encrypt + tag:
   ```python
   cipher = AES.new(key, AES.MODE_EAX, mac_len=4, nonce=nonce)
   ciphertext, tag = cipher.encrypt(payload), cipher.digest()
   ```
6. Pack header: `(version << 2)` (version=2) → 1 byte = `0x08`.
7. Concatenate: `header(1) | nonce_salt(2) | eid_le(8) | ciphertext | tag(4)`.
   - `eid_le = struct.pack("<Q", eid_int)` to match the receive-side `struct.unpack("<Q", raw[3:11])`.
8. Return `EncryptedPacket(timestamp=now, location=_FAKE_LOCATION, payload=<service_data>, rssi=0, protocol_version=2, eid=<eid_int>, auth_tag=<tag>)`.

### CLI dispatch

```
parse_key(key) -> bytes (16 or 32)
parse_payload(payload, payload_format) -> bytes

if len(key) == 32:                         # AES-CTR
    reject EAX-only flags
    pkt = encrypt(key, payload, time_counter=counter, seq_no=seq_no, counter_mode=counter_mode)
elif len(key) == 16:                       # AES-EAX
    reject CTR-only flags
    pkt = encrypt_eax(key, payload, counter=counter, nonce_salt=nonce_salt, period_exponent=period_exponent)

render(pkt, format)
if ingest:
    Organization(...).ingest_packet(pkt)
    print confirmation
```

### Output formats

#### `breakdown` (default)

Human-readable, labeled fields followed by the full service-data bytes in three encodings:

```
Protocol:        AES-EAX (v2)
Key length:      16 bytes
Counter:         0
Period exponent: 0  (period = 1s)
Nonce salt:      0xa3 0xf1
EID:             0x8b3c4d5e6f7a8b9c
Ciphertext:      0xde 0xad 0xbe 0xef
Auth tag:        0x12 0x34 0x56 0x78

Service data (19 bytes):
  Hex:         08a3f19c8b7a6f5e4d3c8bdeadbeef12345678
  Spaced:      08 a3 f1 9c 8b 7a 6f 5e 4d 3c 8b de ad be ef 12 34 56 78
  Python:      b'\x08\xa3\xf1\x9c\x8b\x7a\x6f\x5e\x4d\x3c\x8b\xde\xad\xbe\xef\x12\x34\x56\x78'
  C array:     {0x08, 0xa3, 0xf1, 0x9c, 0x8b, 0x7a, 0x6f, 0x5e, 0x4d, 0x3c, 0x8b, 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78}
```

For AES-CTR the breakdown has the analogous fields (Protocol, Key length, Time counter, Counter mode, Seq no, EID (4-byte), Auth tag, Ciphertext, Service data).

#### `hex`

Single line of hex, no labels, suitable for scripting:

```
08a3f19c8b7a6f5e4d3c8bdeadbeef12345678
```

#### `json`

Machine-readable structured object:

```json
{
  "protocol": "aes_eax",
  "protocol_version": 2,
  "key_length": 16,
  "counter": 0,
  "period_exponent": 0,
  "nonce_salt": "a3f1",
  "eid": "8b3c4d5e6f7a8b9c",
  "ciphertext": "deadbeef",
  "auth_tag": "12345678",
  "service_data": "08a3f19c8b7a6f5e4d3c8bdeadbeef12345678"
}
```

(Analogous shape for AES-CTR with `protocol="aes_ctr"`, `time_counter`, `counter_mode`, `seq_no`.)

### Error handling

| Condition | Behavior |
|---|---|
| Invalid key (not 16 or 32 bytes) | `_parse_key` raises `ValueError`; CLI surfaces `click.ClickException`. |
| Payload too long for protocol (CTR > MAX_CTR_PAYLOAD or EAX > 9 bytes) | `ValueError` from SDK, `click.UsageError` from CLI. |
| `--seq-no` out of range (not 0..1023) | `click.UsageError`. |
| `--nonce-salt` not exactly 2 bytes | `click.UsageError`. |
| `--period-exponent` out of 0..15 | `click.UsageError`. |
| CTR-only flag with 16-byte key (or vice versa) | `click.UsageError` with explicit message. |
| `--counter-mode DEVICE_UPTIME` with explicit `--counter` not provided | Allowed (defaults to 0). |
| `--ingest` without `HUBBLE_ORG_ID`/`HUBBLE_API_TOKEN` | Same `_get_env_or_fail` path used by `ble scan --ingest`. |
| Backend ingest failure | Propagate `BackendError`; the CLI prints the error and exits non-zero. |

### Testing

New file `tests/test_packet_generation.py` covers SDK primitives. CLI coverage extends the existing `tests/test_cli_*` files (or a new `tests/test_cli_generate.py`).

**SDK round-trip tests:**

- `encrypt(key, payload, time_counter=T, seq_no=S)` → `decrypt(key, packet)` returns matching payload, counter=T, sequence=S. Repeat for AES-128 and AES-256 keys.
- `encrypt_eax(key, payload, counter=C, nonce_salt=N, period_exponent=E)` → `decrypt_eax(key, parse(packet), period_exponent=E)` returns matching payload.
- Determinism: same inputs (including explicit `seq_no` / `nonce_salt`) produce byte-identical output across calls.

**EID verification tests:**

- AES-CTR: assert `_generate_ctr_eid(key, T, keylen)` matches a known-good firmware-generated value for at least one fixed `(key, T)` pair. *(Open: need a reference vector from firmware. If not available, fall back to verifying the EID round-trips through the cloud in an integration test marked `@pytest.mark.integration`.)*
- AES-EAX: existing `_generate_eid` is already tested; add a generation test that confirms the EID embedded in the service data matches `_generate_eid(key, counter*period, period_exponent)`.

**Format dispatch tests:**

- 32-byte key produces protocol_version 0 service data; first byte's top 6 bits are zero.
- 16-byte key produces protocol_version 2 service data; first byte equals `0x08`.

**Validation tests:**

- Oversized payload, mismatched flags-vs-key-length, malformed nonce-salt all raise the right errors.

**CLI tests (using `click.testing.CliRunner`):**

- `hubblenetwork ble generate --key <ctr_key> --payload <hex>` with `--format hex` produces parseable bytes that round-trip through `ble._make_packet` and `decrypt`.
- Same for AES-EAX with `--format hex` and `decrypt_eax`.
- `--format json` produces valid JSON with all expected keys.
- `--format breakdown` includes "Protocol", "Service data", and the hex string.
- `--ingest` calls `Organization.ingest_packet` with the generated packet (mock the network).

## Migration / compatibility

Pure addition; no existing behavior changes. The single internal addition is `_generate_ctr_eid()` in `crypto.py`, used only by the new `encrypt()` function. No changes to `decrypt()`, `decrypt_eax()`, `org.py`, `cloud.py`, or BLE parsing. Adds `encrypt`, `encrypt_eax` to the public API surface.

## Open questions

- **Firmware EID test vector:** Do we have a known-good `(key, time_counter) → EID` pair from the firmware suite that we can pin in `test_packet_generation.py`? If not, the round-trip + integration test cover the algorithm but won't independently verify Python-side parity with C. (This isn't blocking — the firmware function is small and we have its source.)
- **MAX_CTR_PAYLOAD:** What's the actual max ciphertext length the firmware emits for AES-CTR adverts? Need to either grab the constant from `hubble_ble.c` or pick a conservative ceiling (e.g. 17 bytes, matching CTR overhead of 10 + ciphertext within a 27-byte service-data limit). The unencrypted-v1 ceiling of 18 bytes is documented but doesn't apply to CTR directly. Implementer should pin this from firmware before merge.

## Follow-ups

- Make `Organization.ingest_packet` accept `AesEaxPacket` (so BLE-received EAX packets can be ingested through the SDK).
- `--count N` for generating sequences of distinct packets.
- Optional support for protocol v1 (unencrypted) generation.
- Consider verifying the CTR EID in `decrypt()` now that we know the algorithm.
