"""Unit tests for the decryption auto-detection module (`hubblenetwork.detect`).

These exercise the detect/cache/label logic directly — coverage that previously
only existed indirectly through full CLI scan invocations.
"""
from __future__ import annotations

import ast
import inspect
from unittest.mock import MagicMock, patch

from hubblenetwork import DEVICE_UPTIME, UNIX_TIME
from hubblenetwork import detect as detect_mod
from hubblenetwork.detect import (
    CtrCounterModeDetector,
    Detection,
    EaxExponentDetector,
    detect_eid_type,
)


# ---------------------------------------------------------------------------
# CtrCounterModeDetector
# ---------------------------------------------------------------------------


class TestCtrCounterModeDetector:
    def _detector(self, *, auto_detect=True, key_len=32, days=2):
        return CtrCounterModeDetector(
            auto_detect=auto_detect,
            fixed_counter_mode=UNIX_TIME,
            days=days,
            key_len=key_len,
        )

    def test_detects_unix_time(self):
        det = self._detector(key_len=32)

        def fn(**kw):
            return "PKT" if kw.get("counter_mode") == UNIX_TIME else None

        d = det.decrypt(decrypt_fn=fn, cache_key=0xAB)
        assert d.result == "PKT"
        assert d.label == "AES-256-CTR, counter_source=UNIX_TIME"

    def test_detects_device_uptime(self):
        det = self._detector(key_len=16)

        def fn(**kw):
            return "PKT" if kw.get("counter_mode") == DEVICE_UPTIME else None

        d = det.decrypt(decrypt_fn=fn, cache_key=0xAB)
        assert d.result == "PKT"
        assert d.label == "AES-128-CTR, counter_source=DEVICE_UPTIME"

    def test_passes_days_only_for_unix_time(self):
        det = self._detector(days=7)
        seen = []

        def fn(**kw):
            seen.append(kw)
            return "PKT" if kw.get("counter_mode") == DEVICE_UPTIME else None

        det.decrypt(decrypt_fn=fn, cache_key=1)
        unix_kw = next(k for k in seen if k["counter_mode"] == UNIX_TIME)
        uptime_kw = next(k for k in seen if k["counter_mode"] == DEVICE_UPTIME)
        assert unix_kw["days"] == 7
        assert "days" not in uptime_kw

    def test_caches_mode_after_first_hit(self):
        det = self._detector()
        calls = {"n": 0}

        def fn(**kw):
            calls["n"] += 1
            return "PKT" if kw.get("counter_mode") == DEVICE_UPTIME else None

        d1 = det.decrypt(decrypt_fn=fn, cache_key=0xCAFE)
        # First packet sweeps UNIX_TIME (miss) then DEVICE_UPTIME (hit) = 2 calls.
        assert d1.result == "PKT"
        assert calls["n"] == 2

        d2 = det.decrypt(decrypt_fn=fn, cache_key=0xCAFE)
        # Second packet hits the cached DEVICE_UPTIME directly = 1 more call.
        assert d2.result == "PKT"
        assert calls["n"] == 3

    def test_label_set_only_on_first_success(self):
        det = self._detector()

        def fn(**kw):
            return "PKT" if kw.get("counter_mode") == UNIX_TIME else None

        d1 = det.decrypt(decrypt_fn=fn, cache_key=1)
        d2 = det.decrypt(decrypt_fn=fn, cache_key=2)
        assert d1.label is not None
        assert d2.label is None

    def test_wrong_key_returns_none(self):
        det = self._detector()
        d = det.decrypt(decrypt_fn=lambda **kw: None, cache_key=1)
        assert d.result is None
        assert d.label is None

    def test_cache_key_none_disables_caching(self):
        det = self._detector()
        calls = {"n": 0}

        def fn(**kw):
            calls["n"] += 1
            return "PKT" if kw.get("counter_mode") == DEVICE_UPTIME else None

        det.decrypt(decrypt_fn=fn, cache_key=None)
        det.decrypt(decrypt_fn=fn, cache_key=None)
        # Both packets re-sweep (2 calls each) since nothing is cached.
        assert calls["n"] == 4

    def test_omitted_cache_key_shares_one_stream_slot(self):
        # Satellite path omits cache_key; all packets share a single slot, so the
        # second packet hits the cached mode instead of re-sweeping.
        det = self._detector()
        calls = {"n": 0}

        def fn(**kw):
            calls["n"] += 1
            return "PKT" if kw.get("counter_mode") == DEVICE_UPTIME else None

        det.decrypt(decrypt_fn=fn)  # sweep UNIX_TIME (miss) + DEVICE_UPTIME (hit)
        det.decrypt(decrypt_fn=fn)  # cached DEVICE_UPTIME hit only
        assert calls["n"] == 3

    def test_zero_length_payload_is_success(self):
        det = self._detector()
        # b"" is falsy but a valid decryption — must be treated as a hit.
        def fn(**kw):
            return b"" if kw.get("counter_mode") == UNIX_TIME else None

        d = det.decrypt(decrypt_fn=fn, cache_key=1)
        assert d.result == b""
        assert d.label is not None

    def test_no_auto_detect_uses_fixed_mode(self):
        det = CtrCounterModeDetector(
            auto_detect=False, fixed_counter_mode=DEVICE_UPTIME, days=2, key_len=32
        )
        seen = []

        def fn(**kw):
            seen.append(kw["counter_mode"])
            return "PKT"

        d = det.decrypt(decrypt_fn=fn, cache_key=1)
        assert d.result == "PKT"
        assert d.label is None  # no announcement in non-auto mode
        assert seen == [DEVICE_UPTIME]


# ---------------------------------------------------------------------------
# EaxExponentDetector
# ---------------------------------------------------------------------------


class TestEaxExponentDetector:
    def test_detects_correct_exponent(self):
        det = EaxExponentDetector(auto_detect=True, fixed_exponent=15)

        def fn(exp):
            return "PKT" if exp == 11 else None

        d = det.decrypt(decrypt_fn=fn, cache_key=0xAB)
        assert d.result == "PKT"
        assert d.label == (
            "AES-128-EAX, counter_source=DEVICE_UPTIME, "
            "period_exponent=11 (period=2048s)"
        )

    def test_caches_exponent_per_eid(self):
        det = EaxExponentDetector(auto_detect=True, fixed_exponent=15)
        calls = {"n": 0}

        def fn(exp):
            calls["n"] += 1
            return "PKT" if exp == 3 else None

        det.decrypt(decrypt_fn=fn, cache_key=0xAB)
        # Sweep 0,1,2,3 = 4 calls.
        assert calls["n"] == 4
        det.decrypt(decrypt_fn=fn, cache_key=0xAB)
        # Cached exponent 3 hit directly = 1 more call.
        assert calls["n"] == 5

    def test_label_set_only_once(self):
        det = EaxExponentDetector(auto_detect=True, fixed_exponent=15)

        def fn(exp):
            return "PKT" if exp == 0 else None

        d1 = det.decrypt(decrypt_fn=fn, cache_key=1)
        d2 = det.decrypt(decrypt_fn=fn, cache_key=2)
        assert d1.label is not None
        assert d2.label is None

    def test_wrong_key_returns_none(self):
        det = EaxExponentDetector(auto_detect=True, fixed_exponent=15)
        d = det.decrypt(decrypt_fn=lambda exp: None, cache_key=1)
        assert d.result is None
        assert d.label is None

    def test_no_auto_detect_uses_fixed_exponent(self):
        det = EaxExponentDetector(auto_detect=False, fixed_exponent=12)
        seen = []

        def fn(exp):
            seen.append(exp)
            return "PKT"

        d = det.decrypt(decrypt_fn=fn, cache_key=1)
        assert d.result == "PKT"
        assert d.label is None
        assert seen == [12]


# ---------------------------------------------------------------------------
# detect_eid_type
# ---------------------------------------------------------------------------


class TestDetectEidType:
    def test_epoch_only(self):
        pkt = MagicMock()
        mock_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return None if kwargs.get("counter_mode") == "DEVICE_UPTIME" else mock_dec

        with patch("hubblenetwork.detect.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = detect_eid_type(b"k" * 16, [pkt])

        assert enc is pkt
        assert dec is mock_dec
        assert label == "UNIX_TIME"
        assert ambiguous is False

    def test_counter_only(self):
        pkt = MagicMock()
        mock_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return mock_dec if kwargs.get("counter_mode") == "DEVICE_UPTIME" else None

        with patch("hubblenetwork.detect.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = detect_eid_type(b"k" * 16, [pkt])

        assert enc is pkt
        assert dec is mock_dec
        assert label == "DEVICE_UPTIME"
        assert ambiguous is False

    def test_ambiguous(self):
        pkt = MagicMock()
        epoch_dec = MagicMock()
        counter_dec = MagicMock()

        def side_effect(*args, **kwargs):
            return counter_dec if kwargs.get("counter_mode") == "DEVICE_UPTIME" else epoch_dec

        with patch("hubblenetwork.detect.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = detect_eid_type(b"k" * 16, [pkt])

        assert enc is pkt
        assert dec is epoch_dec  # epoch preferred
        assert label == "AMBIGUOUS"
        assert ambiguous is True

    def test_neither(self):
        pkt = MagicMock()

        with patch("hubblenetwork.detect.decrypt", return_value=None):
            enc, dec, label, ambiguous = detect_eid_type(b"k" * 16, [pkt])

        assert enc is None
        assert dec is None
        assert label is None
        assert ambiguous is False

    def test_stops_early_when_both_found(self):
        """Stops after pkts[0] resolves both modes; pkts[1] is never processed."""
        pkt0 = MagicMock()
        pkt1 = MagicMock()

        with patch("hubblenetwork.detect.decrypt", return_value=MagicMock()) as mock_decrypt:
            enc, dec, label, ambiguous = detect_eid_type(b"k" * 16, [pkt0, pkt1])

        # Both modes resolved on pkt0: 1 epoch call + 1 counter call = 2 total.
        assert mock_decrypt.call_count == 2
        assert enc is pkt0
        assert label == "AMBIGUOUS"
        assert ambiguous is True

    def test_advances_to_next_packet_when_first_fails(self):
        """Loop continues past pkts[0] when it fails both modes."""
        pkt0 = MagicMock()
        pkt1 = MagicMock()
        mock_dec = MagicMock()

        def side_effect(*args, **kwargs):
            if args[1] is pkt0:
                return None
            return None if kwargs.get("counter_mode") == "DEVICE_UPTIME" else mock_dec

        with patch("hubblenetwork.detect.decrypt", side_effect=side_effect):
            enc, dec, label, ambiguous = detect_eid_type(b"k" * 16, [pkt0, pkt1])

        assert enc is pkt1
        assert dec is mock_dec
        assert label == "UNIX_TIME"
        assert ambiguous is False


# ---------------------------------------------------------------------------
# Decoupling guard — the whole point of this module
# ---------------------------------------------------------------------------


class TestDecoupling:
    def test_detect_module_does_not_import_click(self):
        source = inspect.getsource(detect_mod)
        tree = ast.parse(source)
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        assert not any(
            name == "click" or name.startswith("click.") for name in imported
        ), f"detect.py must not import click; found imports: {imported}"


# ---------------------------------------------------------------------------
# Detection dataclass
# ---------------------------------------------------------------------------


class TestDetection:
    def test_label_defaults_to_none(self):
        d = Detection(result="x")
        assert d.result == "x"
        assert d.label is None
