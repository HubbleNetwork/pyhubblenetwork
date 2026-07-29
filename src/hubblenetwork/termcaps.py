"""Terminal capability handling: the only module in the package holding glyphs.

Two hard rules keep this safe:

1. **Every ASCII substitute has the same ``len()`` as the glyph it replaces.**
   The tables in ``cli.py`` are fixed-width and do their arithmetic with
   ``len()``, so a substitute of a different length shears every column. There
   is a test asserting this per role.

2. **Nothing here may be reached from a JSON or CSV code path.** Those are
   machine contracts. Every ``json.dumps`` call in the package keeps the default
   ASCII escaping, so JSON is ASCII by construction; CSV writes payload bytes in
   whichever format the caller asked for. Glyphs belong only to human-facing
   rendering.

Why glyphs need to degrade at all: writing ``─`` or ``█`` to a stdout whose
encoding is cp1252, cp437 or ascii raises ``UnicodeEncodeError``, which on
Windows turns ``ble scan`` into a traceback. And most of these characters are
East Asian Width "Ambiguous", so they render double-width under a CJK terminal
configuration and shear the columns even where nothing crashes. The encoding
probe catches the first case; the explicit override exists for the second,
which cannot be detected from the encoding.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, fields


@dataclass(frozen=True)
class Glyphs:
    """One rendering vocabulary. Every field is a single display cell wide.

    ``bar_partials`` is the exception: it is a 7-character string indexed by
    eighths, so it must stay exactly 7 long in every variant.
    """

    rule: str
    bar_full: str
    bar_partials: str
    mark_ok: str
    mark_fail: str
    sep: str
    approx: str


UNICODE = Glyphs(
    rule="─",  # ─
    bar_full="█",  # █
    bar_partials="▏▎▍▌▋▊▉",  # ▏▎▍▌▋▊▉
    mark_ok="✓",  # ✓
    mark_fail="✗",  # ✗
    sep="·",  # ·
    approx="≈",  # ≈
)

# ASCII has no sub-cell fill, so the partial ramp collapses to one tier. That
# keeps bar length monotonic without inventing precision the medium cannot
# show; the exact dBm is already in the adjacent RSSI column.
#
# `sep` is "|" rather than "-" because "-" already means "no value" in these
# tables and appears inside emitted flag names.
ASCII = Glyphs(
    rule="-",
    bar_full="#",
    bar_partials="=======",
    mark_ok="+",
    mark_fail="x",
    sep="|",
    approx="~",
)

# Derived from UNICODE rather than a hand-kept codec denylist, so the probe is
# exact: latin-1 encodes "·" but not "─", and only a real encode attempt knows
# that. Also covers the endless codec aliases for free.
_PROBE = "".join(getattr(UNICODE, f.name) for f in fields(UNICODE))

_TRUTHY = {"1", "true", "yes", "on"}
_FALSEY = {"0", "false", "no", "off"}

# Set only by a command-line flag callback. Module state is deliberately the
# single mutable thing here; tests reset it via an autouse fixture.
_explicit_ascii: bool | None = None
_explicit_no_color: bool | None = None


def reset() -> None:
    """Forget any flag-supplied override. For tests and repeated invocations."""
    global _explicit_ascii, _explicit_no_color
    _explicit_ascii = None
    _explicit_no_color = None


def set_explicit_ascii(value: bool | None) -> None:
    global _explicit_ascii
    _explicit_ascii = value


def set_explicit_no_color(value: bool | None) -> None:
    global _explicit_no_color
    _explicit_no_color = value


def _env_flag(name: str) -> bool | None:
    """Read a tri-state env var: True, False, or unset/empty."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    raw = raw.strip().lower()
    if raw in _TRUTHY:
        return True
    if raw in _FALSEY:
        return False
    return None


def _stream_can_encode(stream) -> bool:
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return False
    try:
        _PROBE.encode(encoding, "strict")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def ascii_mode() -> bool:
    """Whether to render with the ASCII vocabulary.

    Precedence: explicit flag, then ``HUBBLE_ASCII``, then whether both streams
    can actually encode the glyphs. Either stream failing selects ASCII, so
    stdout and stderr never disagree visually.
    """
    if _explicit_ascii is not None:
        return _explicit_ascii
    from_env = _env_flag("HUBBLE_ASCII")
    if from_env is not None:
        return from_env
    return not (_stream_can_encode(sys.stdout) and _stream_can_encode(sys.stderr))


def glyphs() -> Glyphs:
    """The active vocabulary. Recomputed per call so it stays a pure function."""
    return ASCII if ascii_mode() else UNICODE


def sep_pad() -> str:
    """The separator with its surrounding padding, five cells in either mode."""
    return f"  {glyphs().sep}  "


def color_enabled() -> bool:
    """Whether colour is wanted, ignoring whether the stream is a TTY.

    Click decides the TTY question; this decides the parts Click does not
    implement. Click has no ``NO_COLOR`` or ``FORCE_COLOR`` support at any
    version, so both live here.
    """
    if _explicit_no_color:
        return False
    # no-color.org: any non-empty value means disable. An empty string is not a
    # signal, which is why this checks the raw value rather than _env_flag.
    return not os.environ.get("NO_COLOR")


def force_color() -> bool:
    """Whether to emit colour even on a non-TTY, e.g. for CI logs."""
    if not color_enabled():
        return False
    return bool(os.environ.get("FORCE_COLOR"))
