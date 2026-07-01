# hubblenetwork/detect.py
"""Auto-detect the decryption configuration of incoming Hubble packets.

A device's packets are decryptable only once you know how its keys rotate: the
AES-CTR counter source (UNIX_TIME vs DEVICE_UPTIME) or, for AES-128-EAX, the
period exponent. That configuration is not carried in the packet, so when the
caller supplies only a key this module discovers it by trying each candidate
until one decrypts, then caches the winner so the rest of the scan skips the
sweep. Caching is keyed per EID for BLE (a scan can see many devices) and shared
across the whole stream for satellite (no per-packet EID).

Detection returns its outcome as a :class:`Detection` rather than printing —
``result`` is the decrypted packet/payload and ``label`` describes the detected
configuration, set once per scan so the caller can announce it exactly once.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Generic, Optional, TypeVar

from .crypto import DEVICE_UPTIME, UNIX_TIME, decrypt, decrypt_eax
from .packets import AesEaxPacket, EncryptedPacket

T = TypeVar("T")

# Default cache key for streams with no per-packet EID (satellite): all packets
# in the scan share one detected-mode slot.
_SINGLE_STREAM = object()


@dataclass
class Detection(Generic[T]):
    """Outcome of one detect-and-decrypt attempt.

    ``result`` is the decrypted packet (BLE) or payload bytes (satellite), or
    ``None`` if decryption failed. A zero-length payload (``b""``) is a *success*,
    so callers must test ``result is not None`` rather than truthiness.

    ``label`` is the human description of the detected configuration (e.g.
    ``"AES-256-CTR, counter_source=UNIX_TIME"``). It is set only on the *first*
    successful detection of a scan and is ``None`` otherwise — i.e. when decrypt
    failed, when the mode came from cache, or when a configuration was already
    announced this scan.
    """

    result: Optional[T]
    label: Optional[str] = None


def _ctr_variant(key_len: int) -> str:
    """AES-CTR encryption name for a key length (16 bytes -> 128-bit)."""
    return "AES-128-CTR" if key_len == 16 else "AES-256-CTR"


class CtrCounterModeDetector:
    """Per-scan AES-CTR counter-source auto-detection.

    Shared by the BLE and satellite scan paths. The caller supplies a
    packet-bound ``decrypt_fn`` (accepting ``counter_mode`` and, for UNIX_TIME,
    ``days``) so this module never references a concrete decrypt primitive
    directly.

    When ``auto_detect`` is False the ``fixed_counter_mode`` is used directly.
    Otherwise the mode cached under ``cache_key`` is tried first, then UNIX_TIME
    and DEVICE_UPTIME are swept; the first that succeeds is cached and labelled
    once. BLE passes the packet's EID as ``cache_key`` (``None`` for EID-less
    packets, which disables caching); satellite omits it, so all packets share
    one per-stream slot.
    """

    def __init__(
        self,
        *,
        auto_detect: bool,
        fixed_counter_mode: str,
        days: int,
        key_len: int,
    ) -> None:
        self._auto_detect = auto_detect
        self._fixed_counter_mode = fixed_counter_mode
        self._days = days
        self._key_len = key_len
        self._cache: dict = {}
        self._announced = False

    def decrypt(
        self,
        *,
        decrypt_fn: Callable[..., Optional[T]],
        cache_key: object = _SINGLE_STREAM,
    ) -> Detection[T]:
        def _try(mode: str) -> Optional[T]:
            kwargs = {"counter_mode": mode}
            if mode == UNIX_TIME:
                kwargs["days"] = self._days
            return decrypt_fn(**kwargs)

        if not self._auto_detect:
            return Detection(_try(self._fixed_counter_mode))

        if cache_key is not None:
            cached = self._cache.get(cache_key)
            if cached is not None:
                result = _try(cached)
                if result is not None:
                    return Detection(result)

        for mode in (UNIX_TIME, DEVICE_UPTIME):
            result = _try(mode)
            if result is None:
                continue
            if cache_key is not None:
                self._cache[cache_key] = mode
            label = None
            if not self._announced:
                self._announced = True
                variant = _ctr_variant(self._key_len)
                label = f"{variant}, counter_source={mode}"
            return Detection(result, label)
        return Detection(None)


class EaxExponentDetector:
    """Per-scan AES-128-EAX period-exponent auto-detection.

    Mirrors :class:`CtrCounterModeDetector` but sweeps period exponents 0-15 on a
    caller-supplied ``decrypt_fn(period_exponent)``. EAX packets always carry an
    EID, so caching is always keyed on ``cache_key``.
    """

    def __init__(self, *, auto_detect: bool, fixed_exponent: int) -> None:
        self._auto_detect = auto_detect
        self._fixed_exponent = fixed_exponent
        self._cache: dict = {}
        self._announced = False

    def decrypt(
        self,
        *,
        decrypt_fn: Callable[[int], Optional[T]],
        cache_key: object,
    ) -> Detection[T]:
        if not self._auto_detect:
            return Detection(decrypt_fn(self._fixed_exponent))

        cached = self._cache.get(cache_key)
        if cached is not None:
            result = decrypt_fn(cached)
            if result is not None:
                return Detection(result)

        for candidate in range(16):
            result = decrypt_fn(candidate)
            if result is None:
                continue
            self._cache[cache_key] = candidate
            label = None
            if not self._announced:
                self._announced = True
                label = (
                    f"AES-128-EAX, counter_source=DEVICE_UPTIME, "
                    f"period_exponent={candidate} (period={1 << candidate}s)"
                )
            return Detection(result, label)
        return Detection(None)


@dataclass
class LocalKeyConfig:
    """Key configuration detected from a device's live packets.

    ``counter_source`` is the resolved CTR mode, or ``None`` when detection was
    ambiguous (both UNIX_TIME and DEVICE_UPTIME decrypt) — exposed as
    ``counter_source_ambiguous``. ``period_exponent`` is set only for AES-128-EAX.
    """

    encryption: str
    counter_source: Optional[str]
    period_exponent: Optional[int]

    @property
    def counter_source_ambiguous(self) -> bool:
        return self.counter_source is None


@dataclass
class FieldResult:
    """One field's local-vs-backend comparison outcome."""

    field: str
    local: object
    backend: object
    status: str  # "ok" | "fail" | "skipped"
    note: Optional[str] = None


def detect_key_config(key, pkts):
    """Detect the full key configuration from sample packets.

    Returns ``(LocalKeyConfig, packet, decrypted)`` for the first packet that
    decrypts, or ``(None, None, None)`` if none do. ``EncryptedPacket`` is AES-CTR
    (128 vs 256 by key length); a packet that decrypts under both UNIX_TIME and
    DEVICE_UPTIME marks the config ambiguous. ``AesEaxPacket`` is AES-128-EAX,
    always DEVICE_UPTIME, with the period exponent swept over 0-15.

    A zero-length decrypted payload is a success, so results are tested with
    ``is not None`` rather than truthiness.
    """
    ctr_variant = _ctr_variant(len(key))
    for pkt in pkts:
        if isinstance(pkt, EncryptedPacket):
            epoch = decrypt(key, pkt)
            counter = decrypt(key, pkt, counter_mode=DEVICE_UPTIME)
            if epoch is not None and counter is not None:
                # Both modes decrypt: counter_source unresolved (None => ambiguous).
                return LocalKeyConfig(ctr_variant, None, None), pkt, epoch
            if epoch is not None:
                return LocalKeyConfig(ctr_variant, UNIX_TIME, None), pkt, epoch
            if counter is not None:
                return LocalKeyConfig(ctr_variant, DEVICE_UPTIME, None), pkt, counter
        elif isinstance(pkt, AesEaxPacket):
            for exponent in range(16):
                result = decrypt_eax(key, pkt, period_exponent=exponent)
                if result is not None:
                    return (
                        LocalKeyConfig("AES-128-EAX", DEVICE_UPTIME, exponent),
                        pkt,
                        result,
                    )
    return None, None, None


def compare_key_config(local, *, encryption, counter_source, period_exponent):
    """Diff a detected LocalKeyConfig against backend-registered values.

    A backend value of ``None`` (field absent from the response) is ``skipped``,
    never a failure. ``period_exponent`` is compared only for AES-128-EAX. An
    ambiguous local counter_source is ``skipped`` with an explanatory note.
    """
    results = [
        _compare_field("encryption", local.encryption, encryption),
    ]

    if local.counter_source_ambiguous:
        results.append(
            FieldResult(
                "counter_source",
                "AMBIGUOUS",
                counter_source,
                "skipped",
                note="local detection ambiguous (both UNIX_TIME and DEVICE_UPTIME decrypt)",
            )
        )
    else:
        results.append(
            _compare_field("counter_source", local.counter_source, counter_source)
        )

    if local.encryption == "AES-128-EAX":
        results.append(
            _compare_field("period_exponent", local.period_exponent, period_exponent)
        )

    return results


def _compare_field(field, local_value, backend_value):
    if backend_value is None:
        return FieldResult(field, local_value, None, "skipped")
    status = "ok" if local_value == backend_value else "fail"
    return FieldResult(field, local_value, backend_value, status)
