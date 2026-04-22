from __future__ import annotations
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Protocol.KDF import SP800_108_Counter
from datetime import datetime, timezone

from .packets import EncryptedPacket, DecryptedPacket, AesEaxPacket

UNIX_TIME = "UNIX_TIME"
DEVICE_UPTIME = "DEVICE_UPTIME"
_VALID_COUNTER_MODES = {UNIX_TIME, DEVICE_UPTIME}

_HUBBLE_AES_NONCE_SIZE = 12
_HUBBLE_AES_TAG_SIZE = 4


class ParsedPacket:
    """Parsed components from an EncryptedPacket's BLE advertisement payload."""

    __slots__ = ("seq_no", "auth_tag", "encrypted_payload")

    def __init__(self, encrypted_pkt: EncryptedPacket) -> None:
        ble_adv = encrypted_pkt.payload
        self.seq_no: int = int.from_bytes(ble_adv[0:2], "big") & 0x3FF
        self.auth_tag: bytes = ble_adv[6:10]
        self.encrypted_payload: bytes = ble_adv[10:]


def _generate_kdf_key(key: bytes, key_size: int, label: str, context: int) -> bytes:
    label = label.encode()
    context = str(context).encode()

    return SP800_108_Counter(
        key,
        key_size,
        lambda session_key, data: CMAC.new(session_key, data, AES).digest(),
        label=label,
        context=context,
    )


def _get_nonce(key: bytes, time_counter: int, counter: int, keylen: int) -> bytes:
    nonce_key = _generate_kdf_key(key, keylen, "NonceKey", time_counter)

    return _generate_kdf_key(nonce_key, _HUBBLE_AES_NONCE_SIZE, "Nonce", counter)


def _get_encryption_key(
    key: bytes, time_counter: int, counter: int, keylen: int
) -> bytes:
    encryption_key = _generate_kdf_key(key, keylen, "EncryptionKey", time_counter)

    return _generate_kdf_key(encryption_key, keylen, "Key", counter)


def _get_auth_tag(key: bytes, ciphertext: bytes) -> bytes:
    computed_cmac = CMAC.new(key, ciphertext, AES).digest()

    return computed_cmac[:_HUBBLE_AES_TAG_SIZE]


def _aes_decrypt(key: bytes, session_nonce: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CTR, nonce=session_nonce)

    return cipher.decrypt(ciphertext)


def _derive_eid_key(key: bytes, counter: int) -> bytes:
    """Derive the intermediate key (key_0) for EID generation.

    For counters 0-127, the result is identical (high counter bytes are [00 00]).
    """
    counter_bytes = counter.to_bytes(4, "little")
    high_counter_bytes = bytes(reversed(counter_bytes[2:4]))
    msg1 = b"\x00" * 11 + b"\xff" + b"\x00\x00" + high_counter_bytes
    return AES.new(key, AES.MODE_ECB).encrypt(msg1)


def _generate_eid(key: bytes, counter: int, period_exponent: int = 0) -> int:
    """Generate an 8-byte EID for a given counter value using AES-ECB."""
    key_0 = _derive_eid_key(key, counter)
    masked = counter & ~((1 << period_exponent) - 1)
    msg2 = b"\x00" * 11 + period_exponent.to_bytes(1, "big") + masked.to_bytes(4, "big")
    eid_block = AES.new(key_0, AES.MODE_ECB).encrypt(msg2)
    return int.from_bytes(eid_block[0:8], "big")


def decrypt_eax(
    key: bytes,
    pkt: AesEaxPacket,
    period_exponent: int = 0,
    pool_size: int = 128,
) -> Optional[DecryptedPacket]:
    """Decrypt an AES-EAX packet by trying candidate counters.

    Generates candidate EIDs for each counter and matches against
    the packet's EID. On match, constructs the nonce and decrypts.

    Args:
        period_exponent: EID rotation period exponent (0-15). Period = 2^n seconds.
            Counter values are multiples of 2**period_exponent. Corresponds to
            rot_exp in device config or log2(period_in_seconds) in the API.
        pool_size: Number of counters to try (default 128).
    """
    step = 1 << period_exponent
    # key_0 is constant when high counter bytes are 00 00 (counter < 65536)
    key_0 = _derive_eid_key(key, 0)
    ecb = AES.new(key_0, AES.MODE_ECB)

    for i in range(pool_size):
        counter = i * step
        msg2 = b"\x00" * 11 + period_exponent.to_bytes(1, "big") + counter.to_bytes(4, "big")
        eid_block = ecb.encrypt(msg2)
        candidate_eid = int.from_bytes(eid_block[0:8], "big")

        if candidate_eid != pkt.eid:
            continue

        # EID matched — construct nonce and decrypt
        nonce = counter.to_bytes(4, "big") + pkt.nonce_salt
        cipher = AES.new(key, AES.MODE_EAX, mac_len=4, nonce=nonce)
        try:
            decrypted = cipher.decrypt_and_verify(
                pkt.payload, pkt.auth_tag
            )
        except ValueError:
            continue

        return DecryptedPacket(
            timestamp=pkt.timestamp,
            device_id="",
            device_name="",
            location=pkt.location,
            tags={},
            payload=decrypted,
            rssi=pkt.rssi,
            counter=i,
            sequence=int.from_bytes(pkt.nonce_salt, "big"),
            protocol_version=pkt.protocol_version,
            eid=pkt.eid,
            auth_tag=pkt.auth_tag,
        )

    return None


def _check_tag_matches(
    key: bytes,
    time_counter: int,
    parsed: ParsedPacket,
) -> bool:
    """Check if the auth_tag matches for the given time_counter."""
    keylen = len(key)
    daily_key = _get_encryption_key(key, time_counter, parsed.seq_no, keylen=keylen)
    tag = _get_auth_tag(daily_key, parsed.encrypted_payload)
    return tag == parsed.auth_tag


def decrypt(
    key: bytes,
    encrypted_pkt: EncryptedPacket,
    days: int = 2,
    counter_mode: str = UNIX_TIME,
) -> Optional[DecryptedPacket]:
    counter_mode = counter_mode.upper()
    if counter_mode not in _VALID_COUNTER_MODES:
        raise ValueError(
            f"counter_mode must be one of {sorted(_VALID_COUNTER_MODES)}, got {counter_mode!r}"
        )
    if counter_mode == DEVICE_UPTIME and days != 2:
        raise ValueError("Cannot specify both counter_mode=DEVICE_UPTIME and days")

    parsed = ParsedPacket(encrypted_pkt)
    keylen = len(key)

    if counter_mode == DEVICE_UPTIME:
        candidates = range(128)
    else:
        time_counter = int(datetime.now(timezone.utc).timestamp()) // 86400
        candidates = (time_counter + t for t in range(-days, days + 1))

    for candidate in candidates:
        if _check_tag_matches(key, candidate, parsed):
            daily_key = _get_encryption_key(
                key, candidate, parsed.seq_no, keylen=keylen
            )
            nonce = _get_nonce(key, candidate, parsed.seq_no, keylen=keylen)
            decrypted_payload = _aes_decrypt(daily_key, nonce, parsed.encrypted_payload)
            return DecryptedPacket(
                timestamp=encrypted_pkt.timestamp,
                device_id="",
                device_name="",
                location=encrypted_pkt.location,
                tags={},
                payload=decrypted_payload,
                rssi=encrypted_pkt.rssi,
                counter=candidate,
                sequence=parsed.seq_no,
                protocol_version=encrypted_pkt.protocol_version,
                eid=encrypted_pkt.eid,
                auth_tag=parsed.auth_tag,
            )
    return None


def find_time_counter_delta(
    key: bytes, encrypted_pkt: EncryptedPacket, max_days_back: int = 365
) -> Optional[int]:
    """
    Find which day counter (time_counter) the key resolves for.

    Returns the delta in days between today (0) and the day the auth_tag matches.
    Positive values mean future days, negative values mean past days.

    Optimization: First checks today (delta=0), then sweeps from 2 days ahead
    backwards through time. Also checks absolute time_counter values 0-365
    in case the device time was erroneously set to epoch.

    Args:
        key: The encryption key
        encrypted_pkt: The encrypted packet to check
        max_days_back: Maximum number of days to search backwards (default 365)

    Returns:
        The delta in days (0 = today, -1 = yesterday, +1 = tomorrow, etc.)
        or None if no matching time_counter is found.
    """
    parsed = ParsedPacket(encrypted_pkt)

    time_counter = int(datetime.now(timezone.utc).timestamp()) // 86400

    # Then sweep from 2 days ahead backwards
    for t in range(2, -max_days_back - 1, -1):
        if _check_tag_matches(key, time_counter + t, parsed):
            return t

    # Check absolute time_counter values 0-365 in case device time was set to epoch
    for absolute_tc in range(366):
        if _check_tag_matches(key, absolute_tc, parsed):
            # Return delta from today's time_counter
            return absolute_tc - time_counter

    return None
