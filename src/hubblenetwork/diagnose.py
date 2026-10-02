# hubblenetwork/diagnose.py
"""Diagnose whether a device's key is set up properly.

Decoupled from the CLI like :mod:`detect`: imports no ``click`` and never
prints. Three sources of evidence are cross-checked:

* the backend registration (:class:`~hubblenetwork.device.Device` from
  ``Organization.get_device``) -- what the cloud will try to decode with;
* the air (:class:`AirScan`) -- what the device is actually broadcasting;
* the firmware build (:func:`inspect_firmware`, optional) -- what the device
  was built to do.

:func:`diagnose` cross-checks them and returns :class:`Finding` rows.

The decrypt helpers all return None for a wrong key, wrong key size, wrong
counter mode and a skewed clock alike, so the air analysis is differential: it
tries each of those hypotheses on purpose and reports which one fits.
"""

from __future__ import annotations

import functools
import os
import pathlib
import re
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from .crypto import (
    DEVICE_UPTIME,
    UNIX_TIME,
    ctr_eid,
    decrypt_at,
    decrypt_eax,
    eax_eid_index,
)
from .device import Device
from .packets import AesEaxPacket, EncryptedPacket

OK = "ok"
FAIL = "fail"
SKIP = "skip"

AES_256_CTR = "AES-256-CTR"
AES_128_CTR = "AES-128-CTR"
AES_128_EAX = "AES-128-EAX"

# Uptime counters live in a fixed pool of 128 (hubble-device-sdk hubble.c).
_UPTIME_POOL = 128
# How far a UNIX_TIME device's clock may be off and still be recognised. Wide
# on purpose: a clock a year out is a finding, not "wrong key".
_CLOCK_DAYS_BEHIND = 366
_CLOCK_DAYS_AHEAD = 30
# The day window decrypt() (and the backend) searches around now.
_CLOCK_TOLERANCE_DAYS = 2
# Cap on distinct EIDs given the slow tag-sweep fallback, for crowded RF.
_MAX_FALLBACK_STREAMS = 32
# The backend must have decoded a packet this recently for the device to pass;
# anything older may predate the reflash or key change being checked.
_BACKEND_FRESH_S = 5 * 60

_NETWORK_NAMES = {"terrestrial": "BLE", "satellite": "satellite"}


@dataclass(frozen=True)
class Finding:
    """One row of the report: same shape as a ``doctor`` check."""

    check: str
    status: str  # OK / FAIL / SKIP
    summary: str
    advice: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Air
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AirMatch:
    """How the device behind this key is actually encrypting."""

    encryption: str  # e.g. AES-256-CTR, or AES-128-CTR when only key[:16] works
    counter_source: str  # UNIX_TIME / DEVICE_UPTIME
    counter: int
    key_variant: str  # "full", or "first16" when the device uses only key[:16]
    authenticated: bool  # False: the EID matched but no payload authenticated
    packets: int = 1  # packets heard from this device
    day_delta: int | None = None  # UNIX_TIME: device day minus today
    period_exponent: int | None = None  # AES-EAX only
    # Decrypted by its auth tag, but its EID is not the one hubble-device-sdk
    # derives from this key: the firmware's EID is wrong, not the key.
    eid_mismatch: bool = False
    # A UNIX_TIME build whose clock was never set: a counter in the uptime
    # pool, re-read by diagnose() because the firmware says UNIX_TIME.
    clock_unset: bool = False


@dataclass(frozen=True)
class AirEvidence:
    heard: int  # Hubble (0xFCA6) packets of any kind, from any device
    match: AirMatch | None


def _key_variants(key: bytes) -> list[tuple[str, bytes]]:
    variants = [("full", key)]
    if len(key) == 32:
        # Firmware built with CONFIG_HUBBLE_NETWORK_KEY_128 reads only the
        # first CONFIG_HUBBLE_KEY_SIZE bytes of a 32-byte key array.
        variants.append(("first16", key[:16]))
    return variants


def _ctr_encryption(key: bytes) -> str:
    return AES_256_CTR if len(key) == 32 else AES_128_CTR


@functools.lru_cache(maxsize=4)
def _ctr_eid_table(key: bytes, today: int) -> dict[bytes, tuple[str, bytes, int]]:
    """Every EID this key could be broadcasting, mapped to how it was made."""
    counters = list(range(today - _CLOCK_DAYS_BEHIND, today + _CLOCK_DAYS_AHEAD + 1))
    counters += range(_UPTIME_POOL)
    table: dict[bytes, tuple[str, bytes, int]] = {}
    for name, vkey in _key_variants(key):
        for counter in counters:
            table.setdefault(ctr_eid(vkey, counter), (name, vkey, counter))
    return table


def _ctr_match(
    name: str, vkey: bytes, counter: int, today: int, authenticated: bool,
    eid_mismatch: bool = False,
) -> AirMatch:
    uptime = counter < _UPTIME_POOL
    return AirMatch(
        encryption=_ctr_encryption(vkey),
        counter_source=DEVICE_UPTIME if uptime else UNIX_TIME,
        counter=counter,
        key_variant=name,
        authenticated=authenticated,
        day_delta=None if uptime else counter - today,
        eid_mismatch=eid_mismatch,
    )


def _match_ctr(key: bytes, pkt, table: dict, today: int, sweep: bool) -> AirMatch | None:
    hit = table.get(bytes(pkt.payload[2:6]))
    if hit is not None:
        name, vkey, counter = hit
        return _ctr_match(name, vkey, counter, today, decrypt_at(vkey, pkt, counter) is not None)
    if not sweep:
        return None
    # Not an EID the SDK derives from this key. If the auth tag still decrypts
    # (within decrypt()'s window), the key is right and the firmware's EID is not.
    window = _CLOCK_TOLERANCE_DAYS
    for name, vkey in _key_variants(key):
        for counter in (*range(today - window, today + window + 1), *range(_UPTIME_POOL)):
            if decrypt_at(vkey, pkt, counter) is not None:
                return _ctr_match(name, vkey, counter, today, True, eid_mismatch=True)
    return None


def _match_eax(key: bytes, pkt) -> AirMatch | None:
    for name, vkey in _key_variants(key):
        for exponent in range(16):
            index = eax_eid_index(vkey, pkt, exponent)
            if index is not None:
                return AirMatch(
                    encryption=AES_128_EAX if len(vkey) == 16 else "AES-256-EAX",
                    counter_source=DEVICE_UPTIME,
                    counter=index,
                    key_variant=name,
                    authenticated=decrypt_eax(vkey, pkt, period_exponent=exponent) is not None,
                    period_exponent=exponent,
                )
    return None


class AirScan:
    """Find the device broadcasting with ``key``, one packet at a time.

    Packets are grouped by EID, so other Hubble devices in range are ignored
    rather than counted as failures. Each new EID is tested against the key as
    given and, for a 32-byte key, its first 16 bytes; for AES-CTR across
    UNIX_TIME day counters from a year back to a month ahead and the
    DEVICE_UPTIME pool, and for AES-EAX across every rotation period exponent.

    :meth:`add` returns True once a packet from this key has authenticated,
    so it can serve as ``ble.scan(until=...)`` and end the scan early.
    """

    def __init__(self, key: bytes, now: float | None = None) -> None:
        self.key = key
        self.today = int(time.time() if now is None else now) // 86400
        self.heard = 0
        self.found = False
        # Built here (~60 ms), not in the BLE callback: there it is a lookup.
        self._table = _ctr_eid_table(key, self.today)
        self._matches: dict[tuple, AirMatch | None] = {}
        self._counts: dict[tuple, int] = {}
        self._swept = 0

    def add(self, pkt) -> bool:
        self.heard += 1
        if isinstance(pkt, EncryptedPacket) and len(pkt.payload) >= 10:
            sid = ("ctr", bytes(pkt.payload[2:6]))
        elif isinstance(pkt, AesEaxPacket):
            sid = ("eax", pkt.eid)
        else:
            return self.found
        self._counts[sid] = self._counts.get(sid, 0) + 1
        if sid not in self._matches:
            m = self._matches[sid] = self._first_match(sid, pkt)
        else:
            m = self._matches[sid]
            # An EID match whose earlier payload failed: later packets get a chance.
            if m is not None and not m.authenticated and self._authenticates(m, pkt):
                m = self._matches[sid] = replace(m, authenticated=True)
        self.found = self.found or (m is not None and m.authenticated)
        return self.found

    def _first_match(self, sid: tuple, pkt) -> AirMatch | None:
        if sid[0] == "eax":
            return _match_eax(self.key, pkt)
        sweep = sid[1] not in self._table and self._swept < _MAX_FALLBACK_STREAMS
        self._swept += sweep
        return _match_ctr(self.key, pkt, self._table, self.today, sweep)

    def _authenticates(self, m: AirMatch, pkt) -> bool:
        vkey = self.key if m.key_variant == "full" else self.key[:16]
        if m.period_exponent is not None:
            return decrypt_eax(vkey, pkt, period_exponent=m.period_exponent) is not None
        return decrypt_at(vkey, pkt, m.counter) is not None

    def evidence(self) -> AirEvidence:
        matches = [
            replace(m, packets=self._counts[sid])
            for sid, m in self._matches.items() if m is not None
        ]
        best = max(matches, key=lambda m: (m.authenticated, m.packets), default=None)
        return AirEvidence(heard=self.heard, match=best)


# ---------------------------------------------------------------------------
# Firmware
# ---------------------------------------------------------------------------

_CONFIG_NAMES = (".config", "sdkconfig", "autoconf.h", "sdkconfig.h")
_IMAGE_SUFFIXES = {".elf", ".bin", ".hex", ".ihex", ".out", ".axf"}
_HEX_SUFFIXES = {".hex", ".ihex"}
_PRUNE_DIRS = {"CMakeFiles", ".git", "__pycache__", "node_modules", "Kconfig"}
_MAX_DEPTH = 5
_MAX_IMAGES = 32
_MAX_IMAGE_BYTES = 64 * 1024 * 1024

_KCONFIG_LINE = re.compile(
    r"^\s*(?:#define\s+)?CONFIG_(HUBBLE_[A-Z0-9_]+)(?:\s*=\s*|\s+)(\S+)"
)
_KCONFIG_UNSET = re.compile(r"^\s*#\s*CONFIG_(HUBBLE_[A-Z0-9_]+) is not set")

# Hubble Device Configuration Vector. hubble-device-sdk's src/utils/hdcv.h
# builds it from the CONFIG_HUBBLE_* macros and compiles it into the image,
# e.g. "HDCV:1.0/E:128/CS:UT/RP:S86400/N:T/TV:0".
_HDCV = re.compile(rb"HDCV:[0-9]+\.[0-9]+(?:/[A-Z]{1,3}:[A-Za-z0-9]+)*")
_HDCV_ENCRYPTION = {"256": AES_256_CTR, "128": AES_128_CTR}
_HDCV_COUNTER = {"UT": UNIX_TIME, "DU": DEVICE_UPTIME}


@dataclass(frozen=True)
class FirmwareEvidence:
    path: str
    # Where encryption/counter_source came from: "image" (the HDCV string
    # compiled into the firmware) or "kconfig" (.config/sdkconfig/autoconf.h).
    config_source: str | None = None
    encryption: str | None = None
    counter_source: str | None = None
    hdcv: str | None = None
    hdcv_image: str | None = None
    hdcv_variants: tuple[str, ...] = ()  # distinct HDCVs across all images
    config_path: str | None = None  # the Kconfig file, when one was read
    # What config_path says where it disagrees with the image (a stale build
    # tree), e.g. "AES-256-CTR"; None when they agree or only one exists.
    config_conflict: str | None = None
    key_in_secure_storage: bool = False  # CONFIG_HUBBLE_NETWORK_CRYPTO_PSA_USE_KEY_ID
    images: tuple[str, ...] = ()
    key_found: str | None = None  # "full" / "first16" / "none"; None = no images
    key_image: str | None = None


def parse_kconfig(text: str) -> dict[str, str]:
    """``CONFIG_HUBBLE_*`` values from a .config, sdkconfig or autoconf.h."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        unset = _KCONFIG_UNSET.match(line)
        if unset:
            values[unset.group(1)] = "n"
            continue
        m = _KCONFIG_LINE.match(line)
        if m:
            value = m.group(2).strip('"')
            values[m.group(1)] = "y" if value == "1" else value
    return values


def parse_hdcv(hdcv: str) -> dict[str, str]:
    """``"HDCV:1.0/E:128/CS:UT"`` -> ``{"HDCV": "1.0", "E": "128", "CS": "UT"}``."""
    return dict(part.partition(":")[::2] for part in hdcv.split("/"))


def _hdcv_meaning(hdcv: str) -> tuple[str | None, str | None]:
    fields = parse_hdcv(hdcv)
    return _HDCV_ENCRYPTION.get(fields.get("E", "")), _HDCV_COUNTER.get(fields.get("CS", ""))


def _config_meaning(symbols: dict[str, str]) -> tuple[str | None, str | None, bool]:
    encryption = None
    if symbols.get("HUBBLE_NETWORK_KEY_256") == "y" or symbols.get("HUBBLE_KEY_SIZE") == "32":
        encryption = AES_256_CTR
    elif symbols.get("HUBBLE_NETWORK_KEY_128") == "y" or symbols.get("HUBBLE_KEY_SIZE") == "16":
        encryption = AES_128_CTR
    counter = None
    if symbols.get("HUBBLE_COUNTER_SOURCE_UNIX_TIME") == "y":
        counter = UNIX_TIME
    elif symbols.get("HUBBLE_COUNTER_SOURCE_DEVICE_UPTIME") == "y":
        counter = DEVICE_UPTIME
    secure = symbols.get("HUBBLE_NETWORK_CRYPTO_PSA_USE_KEY_ID") == "y"
    return encryption, counter, secure


def read_intel_hex(text: str) -> list[bytes]:
    """Contiguous data runs from an Intel HEX file, in address order."""
    chunks: list[tuple[int, bytes]] = []
    base = 0
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(":"):
            continue
        try:
            rec = bytes.fromhex(line[1:])
        except ValueError:
            continue
        if len(rec) < 5:
            continue
        length, addr, kind = rec[0], int.from_bytes(rec[1:3], "big"), rec[3]
        data = rec[4 : 4 + length]
        if kind == 0x00:
            chunks.append((base + addr, data))
        elif kind == 0x02:
            base = int.from_bytes(data, "big") << 4
        elif kind == 0x04:
            base = int.from_bytes(data, "big") << 16
        elif kind == 0x01:
            break
    runs: list[bytes] = []
    current = bytearray()
    end = None
    for addr, data in sorted(chunks):
        if end is not None and addr != end:
            runs.append(bytes(current))
            current = bytearray()
        current += data
        end = addr + len(data)
    if current:
        runs.append(bytes(current))
    return runs


def _image_blobs(path: pathlib.Path) -> list[bytes]:
    if path.suffix.lower() in _HEX_SUFFIXES:
        return read_intel_hex(path.read_text(errors="replace"))
    return [path.read_bytes()]


def _walk(root: pathlib.Path):
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(pathlib.Path(dirpath).parts) - root_depth
        dirnames[:] = sorted(
            d for d in dirnames if d not in _PRUNE_DIRS and depth < _MAX_DEPTH
        )
        for name in sorted(filenames):
            yield pathlib.Path(dirpath) / name


def _image_rank(p: pathlib.Path) -> tuple:
    # A project's own output sits under build*/; a vendor SDK checked in next
    # to it (external/, libs/) ships prebuilt images of its own.
    in_build = any(part.lower().startswith("build") for part in p.parts[:-1])
    name = p.name.lower()
    preferred = name.startswith(("zephyr.", "merged", "app")) or "signed" in name
    return (not in_build, not preferred, len(p.parts), name)


def _discover(root: pathlib.Path) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    configs, images = [], []
    for p in _walk(root):
        if p.name in _CONFIG_NAMES:
            configs.append(p)
        elif p.suffix.lower() in _IMAGE_SUFFIXES and "pre0" not in p.name:
            images.append(p)
    # A resolved .config/sdkconfig beats a generated header; shallower wins.
    configs.sort(key=lambda p: (p.suffix == ".h", len(p.parts)))
    images.sort(key=_image_rank)
    return configs, images[:_MAX_IMAGES]


@dataclass(frozen=True)
class _ImageScan:
    path: pathlib.Path
    hdcv: str | None
    key: str  # "full" / "first16" / "none"


def _scan_image(image: pathlib.Path, key: bytes) -> _ImageScan | None:
    try:
        if image.stat().st_size > _MAX_IMAGE_BYTES:
            return None
        blobs = _image_blobs(image)
    except OSError:
        return None
    hdcv = next((m.group().decode() for b in blobs for m in _HDCV.finditer(b)), None)
    if any(key in b for b in blobs):
        found = "full"
    elif len(key) == 32 and any(key[:16] in b for b in blobs):
        found = "first16"
    else:
        found = "none"
    return _ImageScan(image, hdcv, found)


def _kconfig(configs: list[pathlib.Path]) -> tuple[pathlib.Path | None, dict[str, str]]:
    for candidate in configs:
        try:
            parsed = parse_kconfig(candidate.read_text(errors="replace"))
        except OSError:
            continue
        if parsed:
            return candidate, parsed
    return None, {}


def inspect_firmware(path: str | os.PathLike, key: bytes) -> FirmwareEvidence:
    """Read what a firmware build says about its key setup.

    ``path`` is an image (.elf/.bin/.hex/.ihex/.out/.axf), a build or project
    directory, or a config file (.config, sdkconfig, autoconf.h).

    Key size and counter source come first from the HDCV string that
    hubble-device-sdk compiles into the image: it is what the board actually
    runs, it works for any build system, and it needs nothing but the file
    that was flashed. Kconfig files are the fallback, for SDKs older than HDCV.

    The images are also searched for ``key``'s bytes: a compiled-in key appears
    verbatim, and only its first half being present
    means the build holds a 16-byte key. Images carrying an HDCV are preferred,
    which passes over a vendor SDK's prebuilt bootloaders in the same tree.
    """
    root = pathlib.Path(path)
    if root.is_dir():
        configs, images = _discover(root)
    elif root.suffix.lower() in _IMAGE_SUFFIXES:
        configs, images = [], [root]
    else:
        configs, images = [root], []

    scans = [s for s in (_scan_image(i, key) for i in images) if s is not None]
    scans.sort(key=lambda s: s.hdcv is None)  # stable: discovery order otherwise

    config_path, symbols = _kconfig(configs)
    k_encryption, k_counter, secure = _config_meaning(symbols)

    best = next((s for s in scans if s.hdcv), None)
    conflict = None
    if best is not None:
        source = "image"
        encryption, counter = _hdcv_meaning(best.hdcv)
        stale = [k for k, h in ((k_encryption, encryption), (k_counter, counter))
                 if k and h and k != h]
        if config_path and stale:
            conflict = ", ".join(stale)
    else:
        source = "kconfig" if config_path else None
        encryption, counter = k_encryption, k_counter

    hit = next((s for s in scans if s.key == "full"), None) or next(
        (s for s in scans if s.key == "first16"), None
    )
    key_found = (hit.key if hit else "none") if scans else None

    return FirmwareEvidence(
        path=str(root),
        config_source=source,
        encryption=encryption,
        counter_source=counter,
        hdcv=best.hdcv if best else None,
        hdcv_image=str(best.path) if best else None,
        hdcv_variants=tuple(dict.fromkeys(s.hdcv for s in scans if s.hdcv)),
        config_path=str(config_path) if config_path else None,
        config_conflict=conflict,
        key_in_secure_storage=secure,
        images=tuple(str(s.path) for s in scans),
        key_found=key_found,
        key_image=str(hit.path) if hit else None,
    )


# ---------------------------------------------------------------------------
# Cross-check
# ---------------------------------------------------------------------------


def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def _registered_as(device: Device) -> str:
    parts = [device.encryption or "unknown encryption"]
    if device.counter_source:
        parts.append(device.counter_source)
    if device.period_exponent is not None:
        parts.append(f"period 2^{device.period_exponent}s")
    return ", ".join(parts)


def _registration(device: Device) -> Finding:
    name = f" '{device.name}'" if device.name else ""
    return Finding("Registration", OK, f"{_registered_as(device)}{name}")


def _backend(device: Device, now: float) -> Finding:
    within_s = _BACKEND_FRESH_S
    last = device.last_packet_ts or {}
    if not last:
        return Finding("Backend", FAIL, "has never decoded a packet from this device")
    network, ts = max(last.items(), key=lambda kv: kv[1])
    via = _NETWORK_NAMES.get(network, network)
    age = now - ts
    if age <= within_s:
        return Finding(
            "Backend", OK, f"your packets are being decoded (last {_ago(age)} ago, {via})",
        )
    if age <= 86400:
        advice = (
            "That packet may predate a reflash or key change, which is the point",
            "of checking. A slow advertiser or gateway can also lag, so re-run",
            "in a few minutes if the rows below look right.",
        )
    else:
        advice = (
            "It worked before, so something changed: a reflash, a new key,",
            "a dead battery, or the device left gateway coverage.",
        )
    return Finding(
        "Backend",
        FAIL,
        f"last decoded {_ago(age)} ago ({via}), nothing in the last {_ago(within_s)}",
        advice,
    )


def _shown(path: str | None, root: str) -> str:
    """``path`` relative to the --firmware argument, which the user just typed."""
    if path is None:
        return ""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:  # different drive on Windows
        return path
    if rel == ".":  # --firmware named the file itself
        return os.path.basename(path)
    return path if rel.startswith("..") else rel


def _firmware(fw: FirmwareEvidence) -> list[Finding]:
    rows = []
    bits = ", ".join([fw.encryption or "key size not set",
                      fw.counter_source or "counter source not set"])
    if fw.config_source == "image":
        advice = [fw.hdcv]
        if len(fw.hdcv_variants) > 1:
            advice.append(f"{len(fw.hdcv_variants)} images carry different configs; pass the")
            advice.append("one you flashed to --firmware to check just that one.")
        if fw.config_conflict:
            advice.append(f"{_shown(fw.config_path, fw.path)} says {fw.config_conflict}:"
                          " a stale build tree?")
            advice.append("The image is what the board runs, so it wins.")
        rows.append(Finding(
            "Firmware", OK, f"{bits}  ({_shown(fw.hdcv_image, fw.path)})", tuple(advice),
        ))
    elif fw.config_source == "kconfig":
        rows.append(Finding(
            "Firmware", OK, f"{bits}  ({_shown(fw.config_path, fw.path)})",
            ("No HDCV string in the images (SDK older than HDCV?); read Kconfig instead.",)
            if fw.images else (),
        ))
    else:
        rows.append(Finding(
            "Firmware",
            SKIP,
            "no Hubble config found",
            ("Point --firmware at the image you flashed (.elf/.hex/.bin), or at its",
             "build directory. It reads the HDCV string hubble-device-sdk compiles",
             "in, or else zephyr/.config, sdkconfig or autoconf.h."),
        ))
    if fw.key_found == "full":
        rows.append(Finding(
            "Firmware key", OK, f"this key is compiled into {_shown(fw.key_image, fw.path)}",
        ))
    elif fw.key_found == "first16":
        rows.append(Finding(
            "Firmware key",
            FAIL,
            f"only the first 16 bytes of this key are in {_shown(fw.key_image, fw.path)}",
            ("The build holds a 16-byte (AES-128) key but the key you have is",
             "32 bytes (AES-256). See the Encryption row."),
        ))
    elif fw.key_found == "none":
        if fw.key_in_secure_storage:
            rows.append(Finding(
                "Firmware key", SKIP, "key lives in PSA key storage, not in the image",
            ))
        else:
            rows.append(Finding(
                "Firmware key",
                SKIP,
                f"this key is not in any of {len(fw.images)} image(s)",
                ("If the key is compiled in (e.g. src/key.c), this build has a",
                 "different key. Fine if you provision it at runtime instead."),
            ))
    return rows


def _air(air: AirEvidence, m: AirMatch | None, timeout: float | None) -> Finding:
    if air.heard == 0:
        window = f" in {timeout:g}s" if timeout else ""
        return Finding(
            "Over the air",
            FAIL,
            f"no Hubble advertisements heard{window}",
            ("Is the device powered and advertising? A phone BLE scanner can tell.",
             "The advertisement needs both the 16-bit Service UUID list (0xFCA6)",
             "and a Service Data field. Slow advertisers may need a longer --timeout."),
        )
    if m is None:
        return Finding(
            "Over the air",
            FAIL,
            "no packets from this key (other Hubble devices were heard)",
            ("Tried AES-256/128-CTR (UNIX_TIME from a year back to a month ahead,",
             "and DEVICE_UPTIME), AES-EAX at every period, and the key's first 16",
             "bytes. So the device is flashed with a different key, or it is out",
             "of range."),
        )
    noun = "packet" if m.packets == 1 else "packets"
    if not m.authenticated:
        return Finding(
            "Over the air",
            FAIL,
            f"the EID matches this key but no payload authenticates ({m.packets} {noun})",
            ("Key and counter are right, but the payload encryption or nonce is",
             "not. That points at the firmware's crypto, not your setup."),
        )
    if m.eid_mismatch:
        return Finding(
            "Over the air",
            FAIL,
            f"{m.packets} {noun} decrypt with this key, but carry the wrong EID",
            ("The key and counter are right, but the firmware derives its EID",
             "differently from hubble-device-sdk (hubble_internal_device_id_get).",
             "The backend looks devices up by EID, so it most likely can't",
             "attribute these packets."),
        )
    mode = m.counter_source
    if m.clock_unset:
        mode += " (clock unset)"
    if m.period_exponent is not None:
        mode += f", period 2^{m.period_exponent}s"
    return Finding("Over the air", OK, f"{m.packets} {noun} from this key: {m.encryption}, {mode}")


def _agreement(check: str, reg: str | None, fw: str | None, air: str | None) -> Finding | None:
    """An OK row, but only when there was something to cross-check.

    A single source has nothing to agree with, and its value is already on
    its own row (Registration, Firmware or Over the air).
    """
    sources = [s for s, v in (("registration", reg), ("firmware", fw), ("air", air)) if v]
    if len(sources) < 2:
        return None
    joined = " and ".join(sources) if len(sources) == 2 else "registration, firmware and air"
    return Finding(check, OK, f"{reg or fw or air}  ({joined} agree)")


def _crosscheck(
    check: str, reg: str | None, fw: str | None, air: str | None,
    fix_firmware: tuple[str, ...], fix_air: tuple[str, ...],
) -> Finding | None:
    """Compare one setting across registration, firmware and air.

    One precedence for every setting: a build that disagrees with the
    registration is the cause, so it is reported ahead of what the air shows;
    then the air; then a board that is not running the build given.
    """
    if reg and fw and fw != reg:
        return Finding(check, FAIL, f"registered {reg}, but the firmware is built for {fw}",
                       fix_firmware)
    if reg and air and air != reg:
        return Finding(check, FAIL, f"registered {reg}, but the device is broadcasting {air}",
                       fix_air)
    if fw and air and fw != air:
        return Finding(check, FAIL, f"firmware config says {fw}, but the device broadcasts {air}",
                       ("The board is not running this build.",))
    return _agreement(check, reg, fw, air)


def _encryption(
    key: bytes, device: Device | None, fw: FirmwareEvidence | None, m: AirMatch | None,
) -> Finding | None:
    reg = device.encryption if device else None
    fw_enc = fw.encryption if fw else None
    air_enc = m.encryption if m else None

    if m and m.key_variant == "first16":
        advice = [
            "The firmware is built for 128-bit keys and reads only the first 16",
            "bytes of your 32-byte key, so the backend (using all 32) never matches.",
            "Fix one side:",
            "  rebuild with CONFIG_HUBBLE_NETWORK_KEY_256=y, or",
            "  hubblenetwork org register-device --encryption AES-128-CTR",
            "  and flash that device's 16-byte key.",
        ]
        if reg == AES_256_CTR:
            advice.append("Note: org register-device defaults to AES-256-CTR.")
        lead = f"registered {reg}, but the device" if reg else "the device"
        return Finding(
            "Encryption",
            FAIL,
            f"{lead} uses only the first 16 bytes of the key (AES-128)",
            tuple(advice),
        )
    if reg:
        want = 16 if reg in (AES_128_CTR, AES_128_EAX) else 32
        if len(key) != want:
            return Finding(
                "Encryption",
                FAIL,
                f"your --key is {len(key)} bytes, but the device is registered {reg}",
                (f"{reg} keys are {want} bytes. This is probably another device's key.",),
            )
    rebuild = (
        f"Rebuild with CONFIG_HUBBLE_NETWORK_KEY_{reg[4:7]}=y, or register a"
        if reg in (AES_256_CTR, AES_128_CTR)
        else "This build only does AES-CTR, so register a"
    )
    return _crosscheck(
        "Encryption", reg, fw_enc, air_enc,
        fix_firmware=(rebuild, f"device with --encryption {fw_enc} and flash its key."),
        fix_air=("Register a device with the encryption the firmware uses:",
                 f"  hubblenetwork org register-device --encryption {air_enc}"),
    )


def _counter(
    device: Device | None, fw: FirmwareEvidence | None, m: AirMatch | None,
) -> Finding | None:
    reg = device.counter_source if device else None
    fw_cs = fw.counter_source if fw else None
    air_cs = m.counter_source if m and m.authenticated else None

    def fix(actual: str | None) -> tuple[str, ...]:
        return (
            f"Fix one side: rebuild with CONFIG_HUBBLE_COUNTER_SOURCE_{reg}=y, or",
            f"  hubblenetwork org register-device --counter-source {actual}",
            "  and flash that device's key.",
        )

    fix_air = fix(air_cs)
    if reg == UNIX_TIME and air_cs == DEVICE_UPTIME:
        # Without --firmware there is nothing to break this tie with; with it,
        # an agreeing UNIX_TIME build was already re-read as an unset clock.
        fix_air += ("(A UNIX_TIME device whose clock reads near 1970 looks the same;",
                    " pass --firmware to tell the two apart.)")
    return _crosscheck("Counter mode", reg, fw_cs, air_cs, fix(fw_cs), fix_air)


def _clock(m: AirMatch | None) -> Finding | None:
    if m is None or not m.authenticated or m.day_delta is None:
        return None
    if m.clock_unset:
        reads = datetime.fromtimestamp(m.counter * 86400, tz=timezone.utc).date()
        return Finding(
            "Clock",
            FAIL,
            f"device clock reads {reads.isoformat()}: Unix time was never set",
            (f"The firmware is UNIX_TIME, so day counter {m.counter} means the clock",
             "started from the 1970 epoch. hubble_init() or hubble_time_set() got",
             "uptime or an unset RTC instead of Unix time.",
             "Set the time:  hubblenetwork ready write-time  (or hubble_time_set()).",
             "Or the board isn't running this image: if you flashed a DEVICE_UPTIME",
             "build, point --firmware at that one."),
        )
    delta = m.day_delta
    if delta == 0:
        return Finding("Clock", OK, "device clock is on today")
    off = f"{abs(delta)} day{'s' if abs(delta) > 1 else ''} {'ahead' if delta > 0 else 'behind'}"
    if abs(delta) <= _CLOCK_TOLERANCE_DAYS:
        return Finding("Clock", OK, f"device clock is {off} (within tolerance)")
    return Finding(
        "Clock",
        FAIL,
        f"device clock is {off}",
        (f"The backend only searches {_CLOCK_TOLERANCE_DAYS} days either side of today.",
         "Set the time:  hubblenetwork ready write-time  (or hubble_time_set())."),
    )


def _period(device: Device | None, m: AirMatch | None) -> Finding | None:
    if m is None or m.period_exponent is None or not m.authenticated:
        return None
    reg = device.period_exponent if device else None
    if reg is not None and reg != m.period_exponent:
        return Finding(
            "Period",
            FAIL,
            f"device rotates every 2^{m.period_exponent}s, registered 2^{reg}s",
            ("Register with the period the firmware uses:",
             "  hubblenetwork org register-device --encryption AES-128-EAX",
             f"    --counter-source DEVICE_UPTIME --period-exponent {m.period_exponent}"),
        )
    return Finding("Period", OK, f"2^{m.period_exponent}s")


def _resolve_epoch_clock(
    m: AirMatch | None, fw: FirmwareEvidence | None, device: Device | None, now: float,
) -> AirMatch | None:
    """Break the tie between DEVICE_UPTIME and a UNIX_TIME clock near 1970.

    A counter in the uptime pool is cryptographically both. When the build is
    UNIX_TIME (and the registration does not say otherwise), it is the clock.
    """
    if (
        m is None
        or not m.authenticated
        or m.counter_source != DEVICE_UPTIME
        or m.period_exponent is not None  # AES-EAX is uptime-only
        or fw is None
        or fw.counter_source != UNIX_TIME
        or (device is not None and device.counter_source not in (None, UNIX_TIME))
    ):
        return m
    return replace(
        m, counter_source=UNIX_TIME, day_delta=m.counter - int(now) // 86400, clock_unset=True,
    )


def diagnose(
    *,
    key: bytes,
    device: Device | None,
    air: AirEvidence | Finding | None,
    firmware: FirmwareEvidence | None = None,
    timeout: float | None = None,
    now: float | None = None,
) -> list[Finding]:
    """Cross-check the gathered evidence; one :class:`Finding` per row.

    ``device`` is the registration, or None when it could not be looked up
    (the caller reports why). ``air`` is the scan's evidence, or a ready-made
    Finding when no scan happened, which keeps its place in the report.
    """
    now = time.time() if now is None else now
    rows: list[Finding] = []
    if device is not None:
        rows.append(_registration(device))
        rows.append(_backend(device, now))
    if firmware is not None:
        rows.extend(_firmware(firmware))
    m = None
    if isinstance(air, Finding):
        rows.append(air)
    elif air is not None:
        m = _resolve_epoch_clock(air.match, firmware, device, now)
        rows.append(_air(air, m, timeout))

    consistency = [
        _encryption(key, device, firmware, m),
        _counter(device, firmware, m),
        _clock(m),
        _period(device, m),
    ]
    rows.extend(r for r in consistency if r is not None)

    # Everything local checks out but nothing reaches the cloud: a radio-path
    # problem, not a key problem. Worth saying outright.
    backend_failed = any(r.check == "Backend" and r.status == FAIL for r in rows)
    setup_failed = any(r.status == FAIL and r.check != "Backend" for r in rows)
    if backend_failed and m is not None and m.authenticated and not setup_failed:
        rows.append(Finding(
            "Delivery",
            FAIL,
            "the key setup is right, but packets are not reaching the backend",
            ("Nothing has relayed this device. Is a Hubble gateway or phone in range?",),
        ))
    return rows
