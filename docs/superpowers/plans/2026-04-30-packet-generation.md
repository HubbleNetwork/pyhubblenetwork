# Packet Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SDK functions and a CLI command (`hubblenetwork ble generate`) that generate AES-CTR (v0) and AES-EAX (v2) Hubble BLE advertisement packets from a key + payload, with optional ingestion to the Hubble Cloud.

**Architecture:** Two pure functions in `crypto.py` (`encrypt`, `encrypt_eax`) that mirror the existing `decrypt` / `decrypt_eax` and reuse the existing KDF / EID / nonce helpers. A new Click subcommand under the `ble` group dispatches by key length (32 → CTR, 16 → EAX), formats output (breakdown / hex / json), and optionally posts the packet via `Organization.ingest_packet`. Both encrypt functions return an `EncryptedPacket` whose `.payload` field is the full BLE service-data byte string — this lets the same struct flow through `org.ingest_packet` regardless of protocol.

**Tech Stack:** Python 3, `pycryptodome` (already a dep), Click, pytest. Reuses existing `_generate_kdf_key`, `_get_encryption_key`, `_get_nonce`, `_get_auth_tag`, `_derive_eid_key` helpers in `crypto.py`.

**Reference:** Spec at `docs/superpowers/specs/2026-04-30-packet-generation-design.md`.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `src/hubblenetwork/crypto.py` | Modify | Add `MAX_CTR_PAYLOAD`, `MAX_EAX_PAYLOAD`, `_generate_ctr_eid`, `encrypt`, `encrypt_eax` |
| `src/hubblenetwork/__init__.py` | Modify | Export `encrypt`, `encrypt_eax` |
| `src/hubblenetwork/cli.py` | Modify | Add `ble generate` subcommand and three output formatters |
| `tests/test_packet_generation.py` | Create | SDK round-trip + validation tests |
| `tests/test_cli_generate.py` | Create | CLI command tests |
| `README.md` | Modify | Add `ble generate` example |

---

## Constants (used across tasks)

These come from firmware (`hubble_ble.c`):

```python
MAX_CTR_PAYLOAD = 13   # HUBBLE_BLE_MAX_DATA_LEN
MAX_EAX_PAYLOAD = 9    # documented in CLAUDE.md / packets.py docstring
```

---

## Task 1: Add CTR EID helper and payload constants

**Files:**
- Modify: `src/hubblenetwork/crypto.py`
- Test: `tests/test_packet_generation.py`

- [ ] **Step 1: Create the test file with the failing test**

Create `tests/test_packet_generation.py`:

```python
"""Tests for packet generation (encrypt / encrypt_eax)."""

from hubblenetwork.crypto import _generate_ctr_eid


class TestGenerateCtrEid:
    def test_returns_4_bytes(self):
        key = bytes(range(32))
        eid = _generate_ctr_eid(key, time_counter=12345, keylen=32)
        assert isinstance(eid, bytes)
        assert len(eid) == 4

    def test_deterministic(self):
        key = bytes(range(32))
        a = _generate_ctr_eid(key, time_counter=12345, keylen=32)
        b = _generate_ctr_eid(key, time_counter=12345, keylen=32)
        assert a == b

    def test_changes_with_time_counter(self):
        key = bytes(range(32))
        a = _generate_ctr_eid(key, time_counter=12345, keylen=32)
        b = _generate_ctr_eid(key, time_counter=12346, keylen=32)
        assert a != b

    def test_aes_128_key(self):
        key = bytes(range(16))
        eid = _generate_ctr_eid(key, time_counter=0, keylen=16)
        assert len(eid) == 4
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `pytest tests/test_packet_generation.py -v`
Expected: 4 failures, all `ImportError: cannot import name '_generate_ctr_eid'`.

- [ ] **Step 3: Add constants and helper to `crypto.py`**

In `src/hubblenetwork/crypto.py`, add the constants near the top (after the existing `_HUBBLE_AES_TAG_SIZE` constant):

```python
# Maximum customer payload sizes (matches firmware HUBBLE_BLE_MAX_DATA_LEN
# and the AES-EAX 0-9 byte ciphertext cap documented in packets.py).
MAX_CTR_PAYLOAD = 13
MAX_EAX_PAYLOAD = 9
```

Then add the EID helper next to `_get_auth_tag` (around line 60):

```python
def _generate_ctr_eid(key: bytes, time_counter: int, keylen: int) -> bytes:
    """Generate the 4-byte AES-CTR EID embedded at offset 2-6 of v0 service data.

    Mirrors the firmware `hubble_internal_device_id_get` function: a two-step
    KBKDF chain. First derives a per-period DeviceKey from the master key,
    then derives the 4-byte DeviceID with seq_no hardcoded to 0.
    """
    device_key = _generate_kdf_key(key, keylen, "DeviceKey", time_counter)
    return _generate_kdf_key(device_key, 4, "DeviceID", 0)
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `pytest tests/test_packet_generation.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/crypto.py tests/test_packet_generation.py
git commit -m "feat(crypto): add _generate_ctr_eid helper and payload size constants"
```

---

## Task 2: Add `encrypt()` for AES-CTR (v0)

**Files:**
- Modify: `src/hubblenetwork/crypto.py`
- Test: `tests/test_packet_generation.py`

- [ ] **Step 1: Add round-trip test**

Append to `tests/test_packet_generation.py`:

```python
import pytest
from hubblenetwork.crypto import (
    encrypt,
    decrypt,
    UNIX_TIME,
    DEVICE_UPTIME,
    MAX_CTR_PAYLOAD,
)


class TestEncryptCtr:
    def test_round_trip_aes_256(self):
        key = bytes(range(32))
        plaintext = b"hello world"
        pkt = encrypt(key, plaintext, time_counter=7, seq_no=42, counter_mode=DEVICE_UPTIME)
        result = decrypt(key, pkt, counter_mode=DEVICE_UPTIME)
        assert result is not None
        assert result.payload == plaintext
        assert result.counter == 7
        assert result.sequence == 42

    def test_round_trip_aes_128(self):
        key = bytes(range(16))
        plaintext = b"hi"
        pkt = encrypt(key, plaintext, time_counter=3, seq_no=100, counter_mode=DEVICE_UPTIME)
        result = decrypt(key, pkt, counter_mode=DEVICE_UPTIME)
        assert result is not None
        assert result.payload == plaintext
        assert result.counter == 3
        assert result.sequence == 100

    def test_unix_time_default(self):
        """Without time_counter, defaults to today's UTC day; decrypt() default mode finds it."""
        key = bytes(range(32))
        pkt = encrypt(key, b"x", seq_no=1)
        result = decrypt(key, pkt)  # default UNIX_TIME, ±2 days
        assert result is not None
        assert result.payload == b"x"
        assert result.sequence == 1

    def test_random_seq_no_when_omitted(self):
        """Without seq_no, two calls produce different bytes."""
        key = bytes(range(32))
        a = encrypt(key, b"x", time_counter=5, counter_mode=DEVICE_UPTIME)
        b = encrypt(key, b"x", time_counter=5, counter_mode=DEVICE_UPTIME)
        assert a.payload != b.payload

    def test_deterministic_with_explicit_inputs(self):
        key = bytes(range(32))
        a = encrypt(key, b"x", time_counter=5, seq_no=7, counter_mode=DEVICE_UPTIME)
        b = encrypt(key, b"x", time_counter=5, seq_no=7, counter_mode=DEVICE_UPTIME)
        assert a.payload == b.payload

    def test_eid_matches_helper(self):
        key = bytes(range(32))
        pkt = encrypt(key, b"x", time_counter=5, seq_no=7, counter_mode=DEVICE_UPTIME)
        # Service data layout: header(2) | EID(4) | auth_tag(4) | ciphertext
        eid_bytes = pkt.payload[2:6]
        assert eid_bytes == _generate_ctr_eid(key, 5, keylen=32)

    def test_protocol_version_zero(self):
        key = bytes(range(32))
        pkt = encrypt(key, b"x", time_counter=5, seq_no=7, counter_mode=DEVICE_UPTIME)
        # Top 6 bits of byte 0 are version (0 for AES-CTR)
        assert (pkt.payload[0] >> 2) == 0
        assert pkt.protocol_version == 0

    def test_seq_no_encoded_in_header(self):
        key = bytes(range(32))
        pkt = encrypt(key, b"x", time_counter=5, seq_no=0x123, counter_mode=DEVICE_UPTIME)
        seq_extracted = int.from_bytes(pkt.payload[0:2], "big") & 0x3FF
        assert seq_extracted == 0x123
```

The `_generate_ctr_eid` import was added at the top of the file in Task 1.

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_packet_generation.py::TestEncryptCtr -v`
Expected: All fail with `ImportError: cannot import name 'encrypt'`.

- [ ] **Step 3: Implement `encrypt()` in `crypto.py`**

Add at the bottom of `src/hubblenetwork/crypto.py` (or grouped with `decrypt`):

```python
import secrets
import time as _time


def encrypt(
    key: bytes,
    payload: bytes,
    *,
    time_counter: Optional[int] = None,
    seq_no: Optional[int] = None,
    counter_mode: str = UNIX_TIME,
) -> EncryptedPacket:
    """Generate an AES-CTR (protocol v0) encrypted Hubble BLE packet.

    The returned EncryptedPacket's `.payload` field holds the full BLE
    service-data byte string: header(2) | EID(4) | auth_tag(4) | ciphertext.
    """
    counter_mode = counter_mode.upper()
    if counter_mode not in _VALID_COUNTER_MODES:
        raise ValueError(
            f"counter_mode must be one of {sorted(_VALID_COUNTER_MODES)}, got {counter_mode!r}"
        )

    keylen = len(key)
    if keylen not in (16, 32):
        raise ValueError(f"key must be 16 or 32 bytes, got {keylen}")

    if len(payload) > MAX_CTR_PAYLOAD:
        raise ValueError(
            f"payload too long for AES-CTR: {len(payload)} > {MAX_CTR_PAYLOAD}"
        )

    if seq_no is None:
        seq_no = secrets.randbelow(1 << 10)
    if not (0 <= seq_no < (1 << 10)):
        raise ValueError(f"seq_no must be in 0..1023, got {seq_no}")

    if time_counter is None:
        if counter_mode == UNIX_TIME:
            time_counter = int(_time.time()) // 86400
        else:
            time_counter = 0

    enc_key = _get_encryption_key(key, time_counter, seq_no, keylen=keylen)
    nonce = _get_nonce(key, time_counter, seq_no, keylen=keylen)
    ciphertext = AES.new(enc_key, AES.MODE_CTR, nonce=nonce).encrypt(payload)
    auth_tag = _get_auth_tag(enc_key, ciphertext)
    eid_bytes = _generate_ctr_eid(key, time_counter, keylen=keylen)

    # Header: top 6 bits = version (0 for v0), bottom 10 bits = seq_no
    header_int = (0 << 10) | (seq_no & 0x3FF)
    header = header_int.to_bytes(2, "big")

    service_data = header + eid_bytes + auth_tag + ciphertext

    from datetime import datetime, timezone
    return EncryptedPacket(
        timestamp=int(datetime.now(timezone.utc).timestamp()),
        location=Location(lat=90, lon=0, fake=True),
        payload=service_data,
        rssi=0,
        protocol_version=0,
        eid=int.from_bytes(eid_bytes, "big"),
        auth_tag=auth_tag,
    )
```

Add the missing import at the top of `crypto.py`:

```python
from .packets import EncryptedPacket, DecryptedPacket, AesEaxPacket, Location
```

(Replace the existing `from .packets import` line — `Location` is the only addition.)

- [ ] **Step 4: Run tests and verify they pass**

Run: `pytest tests/test_packet_generation.py::TestEncryptCtr -v`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/crypto.py tests/test_packet_generation.py
git commit -m "feat(crypto): add encrypt() for AES-CTR packet generation"
```

---

## Task 3: Add `encrypt_eax()` for AES-EAX (v2)

**Files:**
- Modify: `src/hubblenetwork/crypto.py`
- Test: `tests/test_packet_generation.py`

- [ ] **Step 1: Add round-trip test**

Append to `tests/test_packet_generation.py`:

```python
import struct
from hubblenetwork.crypto import encrypt_eax, decrypt_eax
from hubblenetwork import ble as ble_mod
from hubblenetwork.packets import AesEaxPacket


class TestEncryptEax:
    KEY_128 = bytes(range(16))

    def test_round_trip_default(self):
        plaintext = b"abc"
        pkt = encrypt_eax(self.KEY_128, plaintext)
        # Re-parse the service data bytes back into an AesEaxPacket
        parsed = ble_mod._make_packet(pkt.payload, rssi=0)
        assert isinstance(parsed, AesEaxPacket)
        result = decrypt_eax(self.KEY_128, parsed)
        assert result is not None
        assert result.payload == plaintext

    def test_round_trip_with_explicit_inputs(self):
        plaintext = b"abcdefghi"  # 9 bytes, max
        nonce_salt = b"\xa3\xf1"
        pkt = encrypt_eax(
            self.KEY_128, plaintext,
            counter=3, nonce_salt=nonce_salt, period_exponent=0,
        )
        parsed = ble_mod._make_packet(pkt.payload, rssi=0)
        assert isinstance(parsed, AesEaxPacket)
        assert parsed.nonce_salt == nonce_salt
        result = decrypt_eax(self.KEY_128, parsed, period_exponent=0)
        assert result is not None
        assert result.payload == plaintext

    def test_round_trip_with_period_exponent(self):
        plaintext = b"x"
        pkt = encrypt_eax(
            self.KEY_128, plaintext,
            counter=2, nonce_salt=b"\x00\x01", period_exponent=3,
        )
        parsed = ble_mod._make_packet(pkt.payload, rssi=0)
        result = decrypt_eax(self.KEY_128, parsed, period_exponent=3)
        assert result is not None
        assert result.payload == plaintext

    def test_random_nonce_salt_when_omitted(self):
        a = encrypt_eax(self.KEY_128, b"x")
        b = encrypt_eax(self.KEY_128, b"x")
        assert a.payload != b.payload

    def test_deterministic_with_explicit_inputs(self):
        a = encrypt_eax(self.KEY_128, b"x", counter=0, nonce_salt=b"\x00\x00")
        b = encrypt_eax(self.KEY_128, b"x", counter=0, nonce_salt=b"\x00\x00")
        assert a.payload == b.payload

    def test_protocol_version_two(self):
        pkt = encrypt_eax(self.KEY_128, b"x", counter=0, nonce_salt=b"\x00\x00")
        # Top 6 bits of byte 0 = version (2 for AES-EAX) → 0x08
        assert (pkt.payload[0] >> 2) == 2
        assert pkt.protocol_version == 2

    def test_eid_embedded_little_endian(self):
        pkt = encrypt_eax(self.KEY_128, b"", counter=0, nonce_salt=b"\x00\x00")
        # offset 3-11 is the 8-byte EID, little-endian
        embedded_eid = struct.unpack("<Q", pkt.payload[3:11])[0]
        assert pkt.eid == embedded_eid

    def test_returns_encrypted_packet(self):
        """encrypt_eax returns EncryptedPacket so it flows through ingest unchanged."""
        from hubblenetwork.packets import EncryptedPacket as Pkt
        pkt = encrypt_eax(self.KEY_128, b"x")
        assert isinstance(pkt, Pkt)
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_packet_generation.py::TestEncryptEax -v`
Expected: All fail with `ImportError: cannot import name 'encrypt_eax'`.

- [ ] **Step 3: Implement `encrypt_eax()` in `crypto.py`**

Add to `src/hubblenetwork/crypto.py` next to `encrypt()`:

```python
def encrypt_eax(
    key: bytes,
    payload: bytes,
    *,
    counter: Optional[int] = None,
    nonce_salt: Optional[bytes] = None,
    period_exponent: int = 0,
) -> EncryptedPacket:
    """Generate an AES-EAX (protocol v2) encrypted Hubble BLE packet.

    Returns an EncryptedPacket whose `.payload` is the full BLE service-data
    byte string: header(1) | nonce_salt(2) | eid_le(8) | ciphertext | tag(4).
    Returning EncryptedPacket (not AesEaxPacket) keeps Organization.ingest_packet
    working without modification.
    """
    if len(key) != 16:
        raise ValueError(f"AES-EAX requires a 16-byte key, got {len(key)}")
    if len(payload) > MAX_EAX_PAYLOAD:
        raise ValueError(
            f"payload too long for AES-EAX: {len(payload)} > {MAX_EAX_PAYLOAD}"
        )
    if not (0 <= period_exponent <= 15):
        raise ValueError(f"period_exponent must be 0..15, got {period_exponent}")

    if counter is None:
        counter = 0
    if nonce_salt is None:
        nonce_salt = secrets.token_bytes(2)
    elif len(nonce_salt) != 2:
        raise ValueError(f"nonce_salt must be exactly 2 bytes, got {len(nonce_salt)}")

    effective_counter = counter * (1 << period_exponent)

    # Compute EID using the SAME formula decrypt_eax uses (key_0 derived from
    # counter=0). Inlined to guarantee byte-for-byte round-trip even when
    # effective_counter ≥ 65536, where _generate_eid would diverge.
    key_0 = _derive_eid_key(key, 0)
    msg2 = (
        b"\x00" * 11
        + period_exponent.to_bytes(1, "big")
        + effective_counter.to_bytes(4, "big")
    )
    eid_block = AES.new(key_0, AES.MODE_ECB).encrypt(msg2)
    eid_int = int.from_bytes(eid_block[0:8], "big")

    # Build the AES-EAX nonce: counter (BE 4 bytes) || nonce_salt (2 bytes)
    nonce = effective_counter.to_bytes(4, "big") + nonce_salt
    cipher = AES.new(key, AES.MODE_EAX, mac_len=4, nonce=nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(payload)

    # Header byte: version (top 6 bits) shifted up; bottom 2 bits unused for v2
    header = bytes([2 << 2])
    eid_le = struct.pack("<Q", eid_int)
    service_data = header + nonce_salt + eid_le + ciphertext + auth_tag

    from datetime import datetime, timezone
    return EncryptedPacket(
        timestamp=int(datetime.now(timezone.utc).timestamp()),
        location=Location(lat=90, lon=0, fake=True),
        payload=service_data,
        rssi=0,
        protocol_version=2,
        eid=eid_int,
        auth_tag=auth_tag,
    )
```

Add `import struct` at the top of `crypto.py` (next to existing imports).

- [ ] **Step 4: Run tests and verify they pass**

Run: `pytest tests/test_packet_generation.py::TestEncryptEax -v`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/crypto.py tests/test_packet_generation.py
git commit -m "feat(crypto): add encrypt_eax() for AES-EAX packet generation"
```

---

## Task 4: Add validation tests

**Files:**
- Test: `tests/test_packet_generation.py`

- [ ] **Step 1: Add validation tests**

Append to `tests/test_packet_generation.py`:

```python
class TestValidation:
    def test_ctr_invalid_key_length(self):
        with pytest.raises(ValueError, match="16 or 32"):
            encrypt(bytes(20), b"x")

    def test_ctr_payload_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            encrypt(bytes(32), b"x" * 14)

    def test_ctr_seq_no_out_of_range_high(self):
        with pytest.raises(ValueError, match="0..1023"):
            encrypt(bytes(32), b"x", seq_no=1024)

    def test_ctr_seq_no_out_of_range_negative(self):
        with pytest.raises(ValueError, match="0..1023"):
            encrypt(bytes(32), b"x", seq_no=-1)

    def test_ctr_invalid_counter_mode(self):
        with pytest.raises(ValueError, match="counter_mode"):
            encrypt(bytes(32), b"x", counter_mode="GARBAGE")

    def test_eax_invalid_key_length(self):
        with pytest.raises(ValueError, match="16-byte"):
            encrypt_eax(bytes(32), b"x")

    def test_eax_payload_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            encrypt_eax(bytes(16), b"x" * 10)

    def test_eax_nonce_salt_wrong_size(self):
        with pytest.raises(ValueError, match="2 bytes"):
            encrypt_eax(bytes(16), b"x", nonce_salt=b"\x00")

    def test_eax_period_exponent_too_high(self):
        with pytest.raises(ValueError, match="0..15"):
            encrypt_eax(bytes(16), b"x", period_exponent=16)

    def test_eax_period_exponent_negative(self):
        with pytest.raises(ValueError, match="0..15"):
            encrypt_eax(bytes(16), b"x", period_exponent=-1)
```

- [ ] **Step 2: Run tests and verify they pass**

Run: `pytest tests/test_packet_generation.py::TestValidation -v`
Expected: 10 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/test_packet_generation.py
git commit -m "test(crypto): add validation tests for encrypt and encrypt_eax"
```

---

## Task 5: Export `encrypt` and `encrypt_eax` from the package root

**Files:**
- Modify: `src/hubblenetwork/__init__.py`
- Test: `tests/test_packet_generation.py`

- [ ] **Step 1: Add a test that the public exports exist**

Append to `tests/test_packet_generation.py`:

```python
class TestPublicExports:
    def test_encrypt_importable_from_root(self):
        from hubblenetwork import encrypt as e
        assert callable(e)

    def test_encrypt_eax_importable_from_root(self):
        from hubblenetwork import encrypt_eax as e
        assert callable(e)
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_packet_generation.py::TestPublicExports -v`
Expected: 2 failures with `ImportError`.

- [ ] **Step 3: Update `__init__.py`**

Modify `src/hubblenetwork/__init__.py`:

Replace:

```python
from .crypto import decrypt, decrypt_eax, UNIX_TIME, DEVICE_UPTIME
```

with:

```python
from .crypto import decrypt, decrypt_eax, encrypt, encrypt_eax, UNIX_TIME, DEVICE_UPTIME
```

And add `"encrypt"` and `"encrypt_eax"` to `__all__`:

```python
__all__ = [
    "ble",
    "cloud",
    "ready",
    "sat",
    "decrypt",
    "decrypt_eax",
    "encrypt",
    "encrypt_eax",
    "UNIX_TIME",
    "DEVICE_UPTIME",
    ...
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `pytest tests/test_packet_generation.py::TestPublicExports -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/__init__.py tests/test_packet_generation.py
git commit -m "feat: export encrypt and encrypt_eax from package root"
```

---

## Task 6: Add `ble generate` CLI skeleton (dispatch + hex format)

**Files:**
- Modify: `src/hubblenetwork/cli.py`
- Test: `tests/test_cli_generate.py` (create)

- [ ] **Step 1: Create the CLI test file with dispatch tests**

Create `tests/test_cli_generate.py`:

```python
"""Tests for `hubblenetwork ble generate` CLI command."""

import json
import re
import pytest
from click.testing import CliRunner

from hubblenetwork.cli import cli
from hubblenetwork.crypto import decrypt, decrypt_eax, DEVICE_UPTIME
from hubblenetwork.packets import EncryptedPacket, AesEaxPacket, Location
from hubblenetwork import ble as ble_mod


_FAKE_LOCATION = Location(lat=90, lon=0, fake=True)


def _packet_from_hex(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)


class TestBleGenerateHexFormat:
    def test_aes_ctr_hex_round_trips(self):
        runner = CliRunner()
        key_hex = "00" * 32  # 32-byte key, AES-CTR
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", key_hex,
                "--payload", "deadbeef",
                "--payload-format", "hex",
                "--counter-mode", "DEVICE_UPTIME",
                "--counter", "5",
                "--seq-no", "42",
                "--format", "hex",
            ],
        )
        assert result.exit_code == 0, result.output
        hex_out = result.output.strip()
        # Must be a hex string of even length
        assert re.fullmatch(r"[0-9a-fA-F]+", hex_out)
        raw = bytes.fromhex(hex_out)
        # Round-trip: parse raw bytes → decrypt
        pkt = EncryptedPacket(
            timestamp=0, location=_FAKE_LOCATION, payload=raw, rssi=0,
        )
        decrypted = decrypt(bytes(32), pkt, counter_mode=DEVICE_UPTIME)
        assert decrypted is not None
        assert decrypted.payload == bytes.fromhex("deadbeef")
        assert decrypted.counter == 5
        assert decrypted.sequence == 42

    def test_aes_eax_hex_round_trips(self):
        runner = CliRunner()
        key_hex = "00" * 16  # 16-byte key, AES-EAX
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", key_hex,
                "--payload", "deadbeef",
                "--payload-format", "hex",
                "--counter", "0",
                "--nonce-salt", "0001",
                "--period-exponent", "0",
                "--format", "hex",
            ],
        )
        assert result.exit_code == 0, result.output
        raw = bytes.fromhex(result.output.strip())
        parsed = ble_mod._make_packet(raw, rssi=0)
        assert isinstance(parsed, AesEaxPacket)
        decrypted = decrypt_eax(bytes(16), parsed, period_exponent=0)
        assert decrypted is not None
        assert decrypted.payload == bytes.fromhex("deadbeef")


class TestBleGenerateValidation:
    def test_seq_no_with_aes_eax_key_rejected(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 16,
                "--payload", "00",
                "--payload-format", "hex",
                "--seq-no", "1",
                "--format", "hex",
            ],
        )
        assert result.exit_code != 0
        assert "AES-CTR" in result.output or "16-byte" in result.output

    def test_nonce_salt_with_aes_ctr_key_rejected(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 32,
                "--payload", "00",
                "--payload-format", "hex",
                "--nonce-salt", "0001",
                "--format", "hex",
            ],
        )
        assert result.exit_code != 0
        assert "AES-EAX" in result.output or "32-byte" in result.output
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_cli_generate.py -v`
Expected: All fail with "Error: No such command 'generate'" or similar.

- [ ] **Step 3: Add the `ble generate` command and a `_payload_to_bytes` helper to `cli.py`**

In `src/hubblenetwork/cli.py`, find the existing `ble` group definition and add the `generate` subcommand below it. First add the helper near `_parse_key`:

```python
def _payload_to_bytes(payload_str: str, payload_format: str) -> bytes:
    """Decode a payload string into bytes per the chosen format."""
    fmt = payload_format.lower()
    if fmt == "hex":
        return bytes.fromhex(payload_str)
    if fmt == "base64":
        return base64.b64decode(payload_str, validate=True)
    if fmt == "string":
        return payload_str.encode("utf-8")
    raise click.UsageError(f"Unknown payload format: {payload_format}")
```

Then add the command (place it after the `ble_scan` definition):

```python
@ble.command("generate")
@click.option("--key", required=True, help="Encryption key (hex or base64). 16 or 32 bytes.")
@click.option("--payload", required=True, help="Plaintext payload to encrypt.")
@click.option(
    "--payload-format",
    type=click.Choice(["hex", "base64", "string"], case_sensitive=False),
    default="hex",
    show_default=True,
    help="Encoding of --payload.",
)
@click.option(
    "--counter-mode",
    type=click.Choice([UNIX_TIME, DEVICE_UPTIME], case_sensitive=False),
    default=UNIX_TIME,
    show_default=True,
    help="EID counter mode (AES-CTR only).",
)
@click.option("--counter", type=int, default=None, help="time_counter (CTR) or counter index (EAX).")
@click.option("--seq-no", type=int, default=None, help="10-bit sequence number (AES-CTR only).")
@click.option("--nonce-salt", default=None, help="2-byte nonce salt as hex (AES-EAX only).")
@click.option("--period-exponent", type=int, default=0, show_default=True, help="EID rotation period exponent (AES-EAX only). 0..15.")
@click.option("--ingest", is_flag=True, help="POST the generated packet to the Hubble Cloud (requires HUBBLE_ORG_ID/HUBBLE_API_TOKEN).")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["breakdown", "hex", "json"], case_sensitive=False),
    default="breakdown",
    show_default=True,
    help="Output format.",
)
def ble_generate(
    key: str,
    payload: str,
    payload_format: str,
    counter_mode: str,
    counter: Optional[int],
    seq_no: Optional[int],
    nonce_salt: Optional[str],
    period_exponent: int,
    ingest: bool,
    output_format: str,
) -> None:
    """Generate a Hubble BLE encrypted advertisement packet from a key and payload."""
    from hubblenetwork.crypto import encrypt, encrypt_eax

    try:
        key_bytes = _parse_key(key)
    except ValueError as e:
        raise click.UsageError(str(e))

    try:
        payload_bytes = _payload_to_bytes(payload, payload_format)
    except (ValueError, binascii.Error) as e:
        raise click.UsageError(f"Invalid payload: {e}")

    if len(key_bytes) == 32:
        # AES-CTR path
        if nonce_salt is not None:
            raise click.UsageError("--nonce-salt is AES-EAX only; not valid with a 32-byte key.")
        try:
            pkt = encrypt(
                key_bytes,
                payload_bytes,
                time_counter=counter,
                seq_no=seq_no,
                counter_mode=counter_mode,
            )
        except ValueError as e:
            raise click.UsageError(str(e))
    elif len(key_bytes) == 16:
        # AES-EAX path
        if seq_no is not None:
            raise click.UsageError("--seq-no is AES-CTR only; not valid with a 16-byte key.")
        nonce_salt_bytes: Optional[bytes] = None
        if nonce_salt is not None:
            try:
                nonce_salt_bytes = bytes.fromhex(nonce_salt)
            except ValueError as e:
                raise click.UsageError(f"Invalid --nonce-salt hex: {e}")
        try:
            pkt = encrypt_eax(
                key_bytes,
                payload_bytes,
                counter=counter,
                nonce_salt=nonce_salt_bytes,
                period_exponent=period_exponent,
            )
        except ValueError as e:
            raise click.UsageError(str(e))
    else:
        # Defensive — _parse_key already enforces 16/32
        raise click.UsageError(f"Unsupported key length: {len(key_bytes)}")

    # Output
    fmt = output_format.lower()
    if fmt == "hex":
        click.echo(pkt.payload.hex())
    elif fmt == "json":
        click.echo(_render_json(pkt, key_bytes, counter, seq_no, nonce_salt, period_exponent, counter_mode))
    else:  # breakdown — placeholder for now, replaced in Task 7
        click.echo(_render_breakdown(pkt, key_bytes, counter, seq_no, nonce_salt, period_exponent, counter_mode))

    if ingest:
        from hubblenetwork import Organization
        org = Organization(
            org_id=_get_env_or_fail("HUBBLE_ORG_ID"),
            api_token=_get_env_or_fail("HUBBLE_API_TOKEN"),
        )
        org.ingest_packet(pkt)
        click.secho("[INFO] Packet ingested.", fg="green")


def _render_breakdown(pkt, key_bytes, counter, seq_no, nonce_salt, period_exponent, counter_mode):
    """Placeholder breakdown formatter (replaced in Task 7)."""
    return pkt.payload.hex()


def _render_json(pkt, key_bytes, counter, seq_no, nonce_salt, period_exponent, counter_mode):
    """Placeholder JSON formatter (replaced in Task 8)."""
    return json.dumps({"service_data": pkt.payload.hex()})
```

Note: `_get_env_or_fail` already exists in the file — confirm it's defined; if not, define it as:

```python
def _get_env_or_fail(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise click.UsageError(f"Missing required env var: {name}")
    return value
```

(Search `cli.py` first; only add if missing.)

- [ ] **Step 4: Run tests and verify they pass**

Run: `pytest tests/test_cli_generate.py -v`
Expected: 4 passed (2 round-trip, 2 validation).

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_cli_generate.py
git commit -m "feat(cli): add 'ble generate' command with hex output and dispatch"
```

---

## Task 7: Implement `breakdown` formatter

**Files:**
- Modify: `src/hubblenetwork/cli.py`
- Test: `tests/test_cli_generate.py`

- [ ] **Step 1: Add tests for breakdown output**

Append to `tests/test_cli_generate.py`:

```python
class TestBleGenerateBreakdownFormat:
    def test_aes_ctr_breakdown_includes_fields(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 32,
                "--payload", "deadbeef",
                "--payload-format", "hex",
                "--counter-mode", "DEVICE_UPTIME",
                "--counter", "5",
                "--seq-no", "42",
                # no --format → default breakdown
            ],
        )
        assert result.exit_code == 0, result.output
        out = result.output
        assert "AES-CTR" in out
        assert "Service data" in out
        assert "Hex:" in out
        assert "Spaced:" in out
        assert "Python:" in out
        # The hex bytes appear somewhere in the output
        # (we don't assert specific values — those are tested in round-trip tests)

    def test_aes_eax_breakdown_includes_fields(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 16,
                "--payload", "deadbeef",
                "--payload-format", "hex",
                "--counter", "0",
                "--nonce-salt", "0001",
                "--period-exponent", "0",
            ],
        )
        assert result.exit_code == 0, result.output
        out = result.output
        assert "AES-EAX" in out
        assert "Nonce salt" in out
        assert "Period exponent" in out
        assert "Service data" in out
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_cli_generate.py::TestBleGenerateBreakdownFormat -v`
Expected: 2 failures (output doesn't contain expected strings — placeholder formatter).

- [ ] **Step 3: Implement the breakdown formatter**

Replace the `_render_breakdown` placeholder in `cli.py` with:

```python
def _render_breakdown(pkt, key_bytes, counter, seq_no, nonce_salt, period_exponent, counter_mode):
    raw = pkt.payload
    keylen = len(key_bytes)
    is_eax = (keylen == 16)
    lines = []

    if is_eax:
        # Layout: header(1) | salt(2) | eid(8) | ciphertext | tag(4)
        salt = raw[1:3]
        eid_bytes = raw[3:11]
        tag = raw[-4:]
        ciphertext = raw[11:-4]
        period_seconds = 1 << period_exponent
        lines.append(f"Protocol:        AES-EAX (v2)")
        lines.append(f"Key length:      {keylen} bytes")
        lines.append(f"Counter:         {counter if counter is not None else 0}")
        lines.append(f"Period exponent: {period_exponent}  (period = {period_seconds}s)")
        lines.append(f"Nonce salt:      {' '.join(f'0x{b:02x}' for b in salt)}")
        lines.append(f"EID:             0x{pkt.eid:016x}  (LE bytes: {eid_bytes.hex()})")
        lines.append(f"Ciphertext:      {' '.join(f'0x{b:02x}' for b in ciphertext) if ciphertext else '(empty)'}")
        lines.append(f"Auth tag:        {' '.join(f'0x{b:02x}' for b in tag)}")
    else:
        # Layout: header(2) | eid(4) | tag(4) | ciphertext
        header = raw[0:2]
        eid_bytes = raw[2:6]
        tag = raw[6:10]
        ciphertext = raw[10:]
        used_seq = int.from_bytes(header, "big") & 0x3FF
        lines.append(f"Protocol:        AES-CTR (v0)")
        lines.append(f"Key length:      {keylen} bytes")
        lines.append(f"Counter mode:    {counter_mode.upper()}")
        lines.append(f"Time counter:    {counter if counter is not None else '(default)'}")
        lines.append(f"Seq no:          {used_seq}")
        lines.append(f"EID:             0x{int.from_bytes(eid_bytes, 'big'):08x}")
        lines.append(f"Auth tag:        {' '.join(f'0x{b:02x}' for b in tag)}")
        lines.append(f"Ciphertext:      {' '.join(f'0x{b:02x}' for b in ciphertext) if ciphertext else '(empty)'}")

    lines.append("")
    lines.append(f"Service data ({len(raw)} bytes):")
    lines.append(f"  Hex:         {raw.hex()}")
    lines.append(f"  Spaced:      {' '.join(f'{b:02x}' for b in raw)}")
    py_repr = "b'" + "".join(f"\\x{b:02x}" for b in raw) + "'"
    lines.append(f"  Python:      {py_repr}")
    c_array = "{" + ", ".join(f"0x{b:02x}" for b in raw) + "}"
    lines.append(f"  C array:     {c_array}")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `pytest tests/test_cli_generate.py -v`
Expected: All passed (round-trip + validation + breakdown).

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_cli_generate.py
git commit -m "feat(cli): add breakdown output format for 'ble generate'"
```

---

## Task 8: Implement `json` formatter

**Files:**
- Modify: `src/hubblenetwork/cli.py`
- Test: `tests/test_cli_generate.py`

- [ ] **Step 1: Add tests for JSON output**

Append to `tests/test_cli_generate.py`:

```python
class TestBleGenerateJsonFormat:
    def test_aes_ctr_json_shape(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 32,
                "--payload", "ab",
                "--payload-format", "hex",
                "--counter-mode", "DEVICE_UPTIME",
                "--counter", "5",
                "--seq-no", "42",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output.strip())
        assert data["protocol"] == "aes_ctr"
        assert data["protocol_version"] == 0
        assert data["key_length"] == 32
        assert data["counter_mode"] == "DEVICE_UPTIME"
        assert data["time_counter"] == 5
        assert data["seq_no"] == 42
        assert "eid" in data
        assert "auth_tag" in data
        assert "ciphertext" in data
        assert re.fullmatch(r"[0-9a-f]+", data["service_data"])

    def test_aes_eax_json_shape(self):
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 16,
                "--payload", "ab",
                "--payload-format", "hex",
                "--counter", "0",
                "--nonce-salt", "0001",
                "--period-exponent", "0",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output.strip())
        assert data["protocol"] == "aes_eax"
        assert data["protocol_version"] == 2
        assert data["key_length"] == 16
        assert data["counter"] == 0
        assert data["period_exponent"] == 0
        assert data["nonce_salt"] == "0001"
        assert "eid" in data
        assert "auth_tag" in data
        assert "ciphertext" in data
        assert "service_data" in data
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `pytest tests/test_cli_generate.py::TestBleGenerateJsonFormat -v`
Expected: 2 failures (placeholder JSON returns only `service_data`).

- [ ] **Step 3: Implement the JSON formatter**

Replace the `_render_json` placeholder in `cli.py` with:

```python
def _render_json(pkt, key_bytes, counter, seq_no, nonce_salt, period_exponent, counter_mode):
    raw = pkt.payload
    keylen = len(key_bytes)
    if keylen == 16:
        # AES-EAX layout
        salt = raw[1:3]
        eid_bytes = raw[3:11]
        tag = raw[-4:]
        ciphertext = raw[11:-4]
        return json.dumps({
            "protocol": "aes_eax",
            "protocol_version": 2,
            "key_length": keylen,
            "counter": counter if counter is not None else 0,
            "period_exponent": period_exponent,
            "nonce_salt": salt.hex(),
            "eid": eid_bytes.hex(),
            "ciphertext": ciphertext.hex(),
            "auth_tag": tag.hex(),
            "service_data": raw.hex(),
        })
    # AES-CTR layout
    header = raw[0:2]
    eid_bytes = raw[2:6]
    tag = raw[6:10]
    ciphertext = raw[10:]
    used_seq = int.from_bytes(header, "big") & 0x3FF
    return json.dumps({
        "protocol": "aes_ctr",
        "protocol_version": 0,
        "key_length": keylen,
        "counter_mode": counter_mode.upper(),
        "time_counter": counter,
        "seq_no": used_seq,
        "eid": eid_bytes.hex(),
        "ciphertext": ciphertext.hex(),
        "auth_tag": tag.hex(),
        "service_data": raw.hex(),
    })
```

- [ ] **Step 4: Run tests and verify they pass**

Run: `pytest tests/test_cli_generate.py -v`
Expected: All passed.

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_cli_generate.py
git commit -m "feat(cli): add json output format for 'ble generate'"
```

---

## Task 9: Implement `--ingest` flag

**Files:**
- Modify: (CLI already has the flag wired in Task 6 — this task adds tests)
- Test: `tests/test_cli_generate.py`

- [ ] **Step 1: Add tests for `--ingest`**

Append to `tests/test_cli_generate.py`:

```python
from unittest.mock import patch, MagicMock


class TestBleGenerateIngest:
    def test_ingest_calls_organization(self, monkeypatch):
        monkeypatch.setenv("HUBBLE_ORG_ID", "test-org")
        monkeypatch.setenv("HUBBLE_API_TOKEN", "test-token")

        with patch("hubblenetwork.cli.Organization") as MockOrg:
            mock_instance = MagicMock()
            MockOrg.return_value = mock_instance

            runner = CliRunner()
            result = runner.invoke(
                cli,
                [
                    "ble", "generate",
                    "--key", "00" * 32,
                    "--payload", "ab",
                    "--payload-format", "hex",
                    "--counter-mode", "DEVICE_UPTIME",
                    "--counter", "5",
                    "--seq-no", "42",
                    "--format", "hex",
                    "--ingest",
                ],
            )

            assert result.exit_code == 0, result.output
            MockOrg.assert_called_once_with(org_id="test-org", api_token="test-token")
            mock_instance.ingest_packet.assert_called_once()
            # The call's first positional arg is the EncryptedPacket
            ingested_pkt = mock_instance.ingest_packet.call_args[0][0]
            assert isinstance(ingested_pkt, EncryptedPacket)
            assert ingested_pkt.protocol_version == 0

    def test_ingest_aes_eax(self, monkeypatch):
        monkeypatch.setenv("HUBBLE_ORG_ID", "test-org")
        monkeypatch.setenv("HUBBLE_API_TOKEN", "test-token")

        with patch("hubblenetwork.cli.Organization") as MockOrg:
            mock_instance = MagicMock()
            MockOrg.return_value = mock_instance

            runner = CliRunner()
            result = runner.invoke(
                cli,
                [
                    "ble", "generate",
                    "--key", "00" * 16,
                    "--payload", "ab",
                    "--payload-format", "hex",
                    "--counter", "0",
                    "--nonce-salt", "0001",
                    "--format", "hex",
                    "--ingest",
                ],
            )

            assert result.exit_code == 0, result.output
            mock_instance.ingest_packet.assert_called_once()
            ingested_pkt = mock_instance.ingest_packet.call_args[0][0]
            assert ingested_pkt.protocol_version == 2

    def test_ingest_without_credentials_fails(self, monkeypatch):
        monkeypatch.delenv("HUBBLE_ORG_ID", raising=False)
        monkeypatch.delenv("HUBBLE_API_TOKEN", raising=False)
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "ble", "generate",
                "--key", "00" * 32,
                "--payload", "ab",
                "--payload-format", "hex",
                "--counter-mode", "DEVICE_UPTIME",
                "--counter", "5",
                "--seq-no", "42",
                "--format", "hex",
                "--ingest",
            ],
        )
        assert result.exit_code != 0
        assert "HUBBLE_ORG_ID" in result.output
```

- [ ] **Step 2: Add `Organization` import to `cli.py` (top-level if not already)**

`hubblenetwork.cli` already imports `Organization` at the top of the file (`from hubblenetwork import Organization`). The `with patch("hubblenetwork.cli.Organization")` line in the test depends on this. Confirm with:

```bash
grep "from hubblenetwork import Organization" src/hubblenetwork/cli.py
```

Expected: 1 match.

If missing, add it to the imports near the top of the file.

Then update the `ble_generate` function to use the module-level import (remove the `from hubblenetwork import Organization` inside the function body — patch needs the module-level reference):

In `ble_generate`, replace:

```python
    if ingest:
        from hubblenetwork import Organization
        org = Organization(
```

with:

```python
    if ingest:
        org = Organization(
```

- [ ] **Step 3: Run tests and verify they pass**

Run: `pytest tests/test_cli_generate.py::TestBleGenerateIngest -v`
Expected: 3 passed.

- [ ] **Step 4: Run the full test suite**

Run: `pytest tests/test_packet_generation.py tests/test_cli_generate.py -v`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/hubblenetwork/cli.py tests/test_cli_generate.py
git commit -m "test(cli): cover --ingest flag for 'ble generate'"
```

---

## Task 10: Update README with example

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Locate the right section in `README.md`**

Run: `grep -n "ble scan" /Users/paulbuckley/projects/pyhubblenetwork/README.md | head -5`
Find the section showing CLI examples (likely under a "CLI" or "Usage" heading).

- [ ] **Step 2: Add a `ble generate` example after the `ble scan` example**

Insert the following block immediately after the existing `ble scan` example block:

```markdown
### Generate a packet from a key

Produce a well-formed encrypted Hubble BLE packet from a key + payload. Useful
for matching observed hardware emissions against expected output, or for seeding
the cloud with deterministic test data.

```bash
# AES-256-CTR (32-byte key)
hubblenetwork ble generate \
    --key "0000000000000000000000000000000000000000000000000000000000000000" \
    --payload "deadbeef" \
    --payload-format hex \
    --counter-mode DEVICE_UPTIME \
    --counter 5 \
    --seq-no 42

# AES-128-EAX (16-byte key)
hubblenetwork ble generate \
    --key "00000000000000000000000000000000" \
    --payload "deadbeef" \
    --payload-format hex \
    --counter 0 \
    --nonce-salt 0001

# Pipe the raw bytes for scripting
hubblenetwork ble generate --key ... --payload ab --payload-format hex --format hex

# Send the generated packet to the cloud (requires HUBBLE_ORG_ID, HUBBLE_API_TOKEN)
hubblenetwork ble generate --key ... --payload ab --payload-format hex --ingest
```
```

- [ ] **Step 3: Verify markdown renders correctly**

Run: `head -200 README.md | tail -80` (or open in your editor) to spot-check formatting.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(readme): document 'ble generate' command"
```

---

## Task 11: Run full test suite + lint

**Files:** none

- [ ] **Step 1: Run full pytest**

Run: `pytest`
Expected: all tests pass; no failures introduced in unrelated files.

- [ ] **Step 2: Run ruff**

Run: `ruff check src`
Expected: clean (no new violations).

- [ ] **Step 3: If lint fails, fix issues and re-run**

Common things to fix:
- Unused imports — delete them.
- Line-length warnings — wrap long strings or function signatures.

- [ ] **Step 4: Commit any lint fixes (if needed)**

```bash
git add src/
git commit -m "chore: lint fixes for packet generation feature"
```

- [ ] **Step 5: Final verification commit message review**

Run: `git log --oneline | head -15`
Confirm the commits read like a coherent feature series.
