"""Fake Hubble BLE advertisements: correctly encrypted raw 0xFCA6 service data.

The inverse of ``hubblenetwork.crypto.decrypt`` / ``decrypt_eax``, for tests and
scratch scripts (``from tests.fake_packets import make_ctr, as_packet``). The
AES-CTR EID is ``crypto.ctr_eid``, ported from hubble-device-sdk's
``hubble_internal_device_id_get``: the cloud matches on it, so bytes built here
are accepted by the real decode endpoint.

Layouts (the bytes bleak reports as service data, UUID not included):

  AES-CTR  [ver:6=0 | seq:10] (2B BE) | EID (4B) | tag (4B) | ciphertext (<=13B)
  AES-EAX  [ver<<2 = 0x08] (1B) | salt (2B) | EID (8B, little-endian of the
           big-endian AES block int) | ciphertext (0-9B) | tag (4B);
           nonce = counter (4B BE) + salt
"""
from __future__ import annotations

from datetime import datetime, timezone

from Crypto.Cipher import AES

from hubblenetwork import crypto as hc
from hubblenetwork.ble import _make_packet

CTR_MAX_PAYLOAD = 13
EAX_MAX_PAYLOAD = 9


def today_counter() -> int:
    """The UNIX_TIME day counter a device with a correct clock uses now."""
    return int(datetime.now(timezone.utc).timestamp()) // 86400


def ctr_eid(key: bytes, time_counter: int) -> int:
    """The 4-byte AES-CTR EID a device broadcasts for ``time_counter``, as the
    integer the BLE parser puts in ``EncryptedPacket.eid``."""
    return int.from_bytes(hc.ctr_eid(key, time_counter), "big")


def make_ctr(
    key: bytes,
    payload: bytes,
    time_counter: int | None = None,
    seq_no: int = 0,
) -> bytes:
    """AES-128/256-CTR advertisement bytes.

    ``time_counter=None`` means today's UTC day (UNIX_TIME); pass 0-127 for a
    DEVICE_UPTIME counter.
    """
    if len(payload) > CTR_MAX_PAYLOAD:
        raise ValueError(f"payload > {CTR_MAX_PAYLOAD} bytes")
    if time_counter is None:
        time_counter = today_counter()
    kl = len(key)
    ek = hc._get_encryption_key(key, time_counter, seq_no, kl)
    nonce = hc._get_nonce(key, time_counter, seq_no, kl)
    ct = AES.new(ek, AES.MODE_CTR, nonce=nonce).encrypt(payload)
    tag = hc._get_auth_tag(ek, ct)
    hdr = (seq_no & 0x3FF).to_bytes(2, "big")
    return hdr + ctr_eid(key, time_counter).to_bytes(4, "big") + tag + ct


def make_eax(
    key: bytes,
    payload: bytes,
    index: int = 0,
    period_exponent: int = 15,
    salt: bytes = b"\x12\x34",
) -> bytes:
    """AES-128-EAX advertisement bytes. Counter = ``index * 2**period_exponent``."""
    if len(key) != 16:
        raise ValueError("AES-EAX uses a 16-byte key")
    if len(payload) > EAX_MAX_PAYLOAD:
        raise ValueError(f"payload > {EAX_MAX_PAYLOAD} bytes")
    counter = index << period_exponent
    eid = hc._generate_eid(key, counter, period_exponent)
    nonce = counter.to_bytes(4, "big") + salt
    ct, tag = AES.new(key, AES.MODE_EAX, mac_len=4, nonce=nonce).encrypt_and_digest(
        payload
    )
    return bytes([2 << 2]) + salt + eid.to_bytes(8, "little") + ct + tag


def as_packet(raw: bytes, rssi: int = -60, timestamp: int | None = None):
    """Parse ``raw`` exactly as a BLE scan would, optionally pinning the timestamp."""
    pkt = _make_packet(raw, rssi)
    if timestamp is not None:
        from dataclasses import replace

        pkt = replace(pkt, timestamp=timestamp)
    return pkt
