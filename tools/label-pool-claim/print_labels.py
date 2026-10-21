#!/usr/bin/env python3
"""Render 2" x 1" claim labels and print them on a Zebra (ZT411) printer.

Each label: the claim QR code on the left, the device number ("01") large on
the right, "Scan Me!" under it.

    # render only: labels/<device name>.png previews + labels/labels.zpl
    python3 print_labels.py keys/claims.csv --number "Hubble Dual Stack Battery Test=05"

    # ...and print over USB (the Windows print queue for the Zebra)
    python3 print_labels.py keys/claims.csv --printer "ZDesigner ZT411-203dpi ZPL"

    # ...or over the network (the printer's Ethernet port, raw port 9100)
    python3 print_labels.py keys/claims.csv --host 192.168.1.50

    python3 print_labels.py --list-printers

The number is the digits at the end of the device name ("Hubble Dual Stack
03" -> 03); --number NAME=NN sets it for a device whose name has none (or
overrides it). Rows without a number or a claim_token are listed and skipped.

Labels are rendered at the printer's resolution as 1-bit images, so the PNG
preview is exactly what prints, and sent as ZPL ^GFA graphics. Resolution:
--dpi, else read from the queue name ("...-300dpi..."), else 203.

Needs `pip install segno pillow`. The QR codes carry claim tokens, which let
whoever holds one redeem the device, so labels/ is git-ignored like keys/.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import socket
import subprocess
import sys

from internal import common

try:
    import segno
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # checked in main() so --help still works
    segno = None

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT_DIR = os.path.join(HERE, "labels")
DEFAULT_DPI = 203

LABEL_W_IN, LABEL_H_IN = 2.0, 1.0
MARGIN_IN = 0.04      # keep clear of the die-cut edge / registration slop
GAP_IN = 0.04         # between the QR code and the text
TEXT_RIGHT_EXTRA_IN = 0.125  # extra room between the text and the label's end
QUIET_MODULES = 2     # white border around the QR, in modules

FONT_CANDIDATES = (
    r"C:\Windows\Fonts\arialbd.ttf",
    "/Library/Fonts/Arial Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
)

TRAILING_NUMBER = re.compile(r"(\d+)\s*$")


@dataclasses.dataclass
class Label:
    name: str
    number: str
    url: str


# --------------------------------------------------------------------------
# Choosing what to print
# --------------------------------------------------------------------------


def parse_overrides(pairs: list[str]) -> dict[str, str]:
    out = {}
    for pair in pairs:
        name, sep, number = pair.rpartition("=")
        if not sep or not name.strip() or not number.strip():
            raise ValueError(f"--number wants NAME=NN, got {pair!r}")
        out[name.strip().casefold()] = number.strip()
    return out


def collect(csv_paths: list[str], overrides: dict[str, str],
            match: list[str] | None = None, log=print) -> list[Label]:
    labels: list[Label] = []
    for path in csv_paths:
        pool = common.read_pool(path, required=("actual_device_id",))
        for row in pool.rows:
            name = common.field(pool, row, "device_name") or common.field(pool, row, "actual_device_id")
            if match and not any(m.casefold() in name.casefold() for m in match):
                continue
            token = (row.get("claim_token") or "").strip()
            number = overrides.get(name.casefold())
            if number is None:
                found = TRAILING_NUMBER.search(name)
                number = found.group(1) if found else None
            if not token:
                log(f"  skip {name}: no claim_token")
            elif number is None:
                log(f'  skip {name}: no number at the end of the name '
                    f'(add --number "{name}=NN")')
            else:
                labels.append(Label(name, number, common.claim_url(token)))
    unused = set(overrides) - {label.name.casefold() for label in labels}
    for name in sorted(unused):
        log(f"  note: --number for {name!r} matched no device")
    labels.sort(key=lambda l: (int(l.number) if l.number.isdigit() else 1 << 30, l.name))
    return labels


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def find_font(path: str | None) -> str | None:
    if path:
        return path
    return next((p for p in FONT_CANDIDATES if os.path.isfile(p)), None)


def fit_font(draw, text: str, font_path: str | None, max_w: int, max_h: int):
    """The largest font whose rendered text fits in max_w x max_h."""
    lo, hi, best = 4, max_h * 2, None
    while lo <= hi:
        size = (lo + hi) // 2
        font = (ImageFont.truetype(font_path, size) if font_path
                else ImageFont.load_default(size))
        left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
        if right - left <= max_w and bottom - top <= max_h:
            best, lo = font, size + 1
        else:
            hi = size - 1
    return best


def draw_centered(draw, text: str, font, box: tuple[int, int, int, int]) -> None:
    x0, y0, x1, y1 = box
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    x = x0 + (x1 - x0 - (right - left)) // 2 - left
    y = y0 + (y1 - y0 - (bottom - top)) // 2 - top
    draw.text((x, y), text, font=font, fill=0)


def render(label: Label, dpi: int = DEFAULT_DPI, font_path: str | None = None):
    """A 1-bit image of the label at the printer's resolution."""
    width, height = round(LABEL_W_IN * dpi), round(LABEL_H_IN * dpi)
    margin, gap = round(MARGIN_IN * dpi), round(GAP_IN * dpi)
    img = Image.new("L", (width, height), 255)
    draw = ImageDraw.Draw(img)

    # QR: whole dots per module, so every module prints the same size.
    matrix = segno.make_qr(label.url, error="m").matrix
    modules = len(matrix) + 2 * QUIET_MODULES
    dot = (height - 2 * margin) // modules
    if dot < 3:
        raise ValueError(f"QR code needs at least 3 dots per module to scan "
                         f"reliably; only {dot} fit at {dpi} dpi")
    side = dot * modules
    qx, qy = margin, (height - side) // 2
    for r, row in enumerate(matrix):
        for c, on in enumerate(row):
            if on:
                x = qx + (c + QUIET_MODULES) * dot
                y = qy + (r + QUIET_MODULES) * dot
                draw.rectangle((x, y, x + dot - 1, y + dot - 1), fill=0)

    # Text: number on top ~65%, "Scan Me!" under it.
    tx0 = qx + side + gap
    tx1 = width - margin - round(TEXT_RIGHT_EXTRA_IN * dpi)
    ty0, ty1 = margin, height - margin
    split = ty0 + round((ty1 - ty0) * 0.65)
    font_path = find_font(font_path)
    for text, box in ((label.number, (tx0, ty0, tx1, split)),
                      ("Scan Me!", (tx0, split + gap // 2, tx1, ty1))):
        font = fit_font(draw, text, font_path, box[2] - box[0], box[3] - box[1])
        draw_centered(draw, text, font, box)

    # Threshold (not dither) so the preview is exactly the dots that print.
    return img.point(lambda v: 255 if v >= 128 else 0, mode="1")


# --------------------------------------------------------------------------
# ZPL
# --------------------------------------------------------------------------

_INVERT = bytes(255 - i for i in range(256))


def to_zpl(img, copies: int = 1) -> str:
    """One label as a ZPL job, the image as an ^GFA graphic field."""
    width, height = img.size
    row_bytes = (width + 7) // 8
    # PIL "1" packs white as 1; ZPL wants black as 1. Invert, then clear the
    # padding bits past the right edge so they don't print as a black stripe.
    raw = bytearray(img.tobytes().translate(_INVERT))
    pad_mask = (0xFF << (row_bytes * 8 - width)) & 0xFF
    for r in range(height):
        raw[r * row_bytes + row_bytes - 1] &= pad_mask
    total = len(raw)
    return (f"^XA\n^PW{width}\n^LL{height}\n^LH0,0\n"
            f"^FO0,0^GFA,{total},{total},{row_bytes},{raw.hex().upper()}^FS\n"
            f"^PQ{copies}\n^XZ\n")


# --------------------------------------------------------------------------
# Sending
# --------------------------------------------------------------------------


def blank_zpl(dpi: int, count: int) -> str:
    """`count` labels with nothing on them (feeds labels out, e.g. to the
    tear-off point). A white box keeps the format from being empty."""
    width, height = round(LABEL_W_IN * dpi), round(LABEL_H_IN * dpi)
    return (f"^XA\n^PW{width}\n^LL{height}\n^LH0,0\n"
            f"^FO0,0^GB{width},{height},{height},W^FS\n^PQ{count}\n^XZ\n")


def send(args, data: bytes) -> int:
    try:
        if args.printer:
            send_windows_raw(args.printer, data)
        else:
            send_tcp(args.host, data)
    except OSError as exc:
        print(f"error: could not send to the printer: {exc}", file=sys.stderr)
        return 2
    print(f"sent to {args.printer or args.host}")
    return 0


def dpi_from_printer_name(name: str | None) -> int | None:
    found = re.search(r"(\d{3})\s*dpi", name or "", re.IGNORECASE)
    return int(found.group(1)) if found else None


def list_printers() -> list[str]:
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-Printer | Select-Object -ExpandProperty Name"],
        capture_output=True, text=True, check=True).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def send_windows_raw(printer: str, data: bytes, doc_name: str = "claim labels") -> None:
    """Hand bytes to a Windows print queue untouched (RAW datatype), the
    standard way to send ZPL through the Zebra driver over USB."""
    import ctypes
    from ctypes import wintypes

    class DOC_INFO_1(ctypes.Structure):
        _fields_ = [("pDocName", wintypes.LPWSTR), ("pOutputFile", wintypes.LPWSTR),
                    ("pDatatype", wintypes.LPWSTR)]

    ws = ctypes.WinDLL("winspool.drv", use_last_error=True)
    ws.OpenPrinterW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.HANDLE),
                                ctypes.c_void_p]
    ws.StartDocPrinterW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                    ctypes.POINTER(DOC_INFO_1)]
    ws.StartDocPrinterW.restype = wintypes.DWORD
    ws.WritePrinter.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD)]
    for fn in ("StartPagePrinter", "EndPagePrinter", "EndDocPrinter", "ClosePrinter"):
        getattr(ws, fn).argtypes = [wintypes.HANDLE]

    def check(ok, what):
        if not ok:
            raise OSError(f"{what} failed: {ctypes.WinError(ctypes.get_last_error())}")

    handle = wintypes.HANDLE()
    check(ws.OpenPrinterW(printer, ctypes.byref(handle), None),
          f"opening printer {printer!r}")
    try:
        doc = DOC_INFO_1(doc_name, None, "RAW")
        check(ws.StartDocPrinterW(handle, 1, ctypes.byref(doc)), "StartDocPrinter")
        try:
            check(ws.StartPagePrinter(handle), "StartPagePrinter")
            written = wintypes.DWORD()
            buf = ctypes.create_string_buffer(data, len(data))
            check(ws.WritePrinter(handle, buf, len(data), ctypes.byref(written)),
                  "WritePrinter")
            if written.value != len(data):
                raise OSError(f"only {written.value} of {len(data)} bytes were sent")
            ws.EndPagePrinter(handle)
        finally:
            ws.EndDocPrinter(handle)
    finally:
        ws.ClosePrinter(handle)


def send_tcp(host: str, data: bytes) -> None:
    """Zebra printers accept raw ZPL on TCP port 9100."""
    host, _, port = host.partition(":")
    with socket.create_connection((host, int(port or 9100)), timeout=10) as sock:
        sock.sendall(data)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", nargs="*", help="CSV(s) with device_name and claim_token")
    parser.add_argument("--number", action="append", default=[], metavar="NAME=NN",
                        help="label number for a device (repeatable)")
    parser.add_argument("--match", action="append", metavar="TEXT",
                        help="only devices whose name contains TEXT (repeatable)")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                        help="where previews and labels.zpl go (default labels/)")
    parser.add_argument("--dpi", type=int, help="printer resolution: 203, 300 or "
                        "600 (default: from the --printer name, else 203)")
    parser.add_argument("--font", help="TTF font file (default Arial Bold)")
    parser.add_argument("--copies", type=int, default=1, help="copies of each label")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--printer", help="Windows print queue to send to (USB)")
    target.add_argument("--host", help="printer IP[:port] to send to over the network")
    parser.add_argument("--list-printers", action="store_true",
                        help="list Windows print queues and exit")
    parser.add_argument("--blank", type=int, metavar="N",
                        help="print N blank labels (needs --printer or --host) and exit")
    args = parser.parse_args(argv)

    if args.list_printers:
        for name in list_printers():
            print(name)
        return 0
    if args.blank is not None:
        if not (args.printer or args.host):
            parser.error("--blank needs --printer or --host")
        if args.blank < 1:
            parser.error("--blank must be at least 1")
        dpi = args.dpi or dpi_from_printer_name(args.printer) or DEFAULT_DPI
        print(f"{args.blank} blank label(s) at {dpi} dpi")
        return send(args, blank_zpl(dpi, args.blank).encode("ascii"))
    if not args.csv:
        parser.error("give at least one CSV")
    if segno is None:
        print("error: needs segno and Pillow: python -m pip install segno pillow",
              file=sys.stderr)
        return 2

    dpi = args.dpi or dpi_from_printer_name(args.printer) or DEFAULT_DPI
    try:
        labels = collect(args.csv, parse_overrides(args.number), args.match)
    except ValueError as exc:
        parser.error(str(exc))
    except (common.PoolError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not labels:
        print("nothing to print")
        return 1

    os.makedirs(args.out_dir, exist_ok=True)
    jobs = []
    for label in labels:
        img = render(label, dpi, args.font)
        preview = os.path.join(args.out_dir, f"{common.file_stem(label.name)}.png")
        img.save(preview, dpi=(dpi, dpi))
        jobs.append(to_zpl(img, args.copies))
        print(f"  {label.number:>4}  {label.name}  -> {os.path.relpath(preview)}")

    zpl_path = os.path.join(args.out_dir, "labels.zpl")
    data = "".join(jobs).encode("ascii")
    with open(zpl_path, "wb") as fh:
        fh.write(data)
    print(f"\n{len(labels)} label(s) at {dpi} dpi -> {os.path.relpath(zpl_path)}")

    if args.printer or args.host:
        return send(args, data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
