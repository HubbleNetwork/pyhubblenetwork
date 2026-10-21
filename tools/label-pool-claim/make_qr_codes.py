#!/usr/bin/env python3
"""Make a claim QR code for every device in one or more CSVs.

Each row's claim_token goes into

    https://dash.hubble.com/claim?claim_token=<token>&type=device

and the QR code for that link is saved as <device_name>.png:

    python3 make_qr_codes.py keys/nrf52_workswith26_20260930-141200.csv
    python3 make_qr_codes.py keys/*.csv --out-dir qr_codes/booth --format svg

Works on any CSV from provision_devices.py, claim_device.py (--csv) or
kiosk/claim_pool.py. Rows without a claim_token are listed and skipped -- run
claim_device.py --csv on the file first.

Codes are generated locally (segno, `pip install segno`); nothing is sent
anywhere. They are static: the link is encoded directly, so they keep working
with no service behind them. A claim_token is bearer-equivalent -- anyone who
scans it can redeem the device -- so treat the output folder like the keys.
"""

from __future__ import annotations

import argparse
import os
import sys

from internal import common
from internal.common import CLAIM_URL, claim_url, file_stem

try:
    import segno
except ImportError:  # checked in main() so --help still works
    segno = None

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT_DIR = os.path.join(HERE, "qr_codes")


def plan(csv_paths: list[str], template: str = CLAIM_URL,
         log=print) -> tuple[list[tuple[str, str]], int]:
    """[(file stem, url)] for every row with a claim_token, and the number of
    rows skipped. A name used twice gets the device ID appended."""
    jobs: list[tuple[str, str, str]] = []
    skipped = 0
    for path in csv_paths:
        pool = common.read_pool(path, required=("actual_device_id",))
        for index, row in enumerate(pool.rows, start=1):
            device_id = common.field(pool, row, "actual_device_id")
            name = common.field(pool, row, "device_name") or device_id
            token = (row.get("claim_token") or "").strip()
            if not token:
                skipped += 1
                log(f"  skip {name} ({os.path.basename(path)} row {index}): "
                    "no claim_token")
                continue
            jobs.append((file_stem(name), device_id, claim_url(token, template)))

    counts: dict[str, int] = {}
    for stem, _, _ in jobs:
        counts[stem.casefold()] = counts.get(stem.casefold(), 0) + 1
    out = []
    for stem, device_id, url in jobs:
        if counts[stem.casefold()] > 1:
            log(f"  note: more than one device is named {stem!r}; "
                f"saving as {stem} {device_id}")
            stem = f"{stem} {device_id}"
        out.append((stem, url))
    return out, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", nargs="+", help="CSV(s) with device_name and claim_token")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                        help="folder to save into (default qr_codes/ next to "
                             "this script)")
    parser.add_argument("--format", choices=("png", "svg"), default="png")
    parser.add_argument("--scale", type=int, default=10,
                        help="pixels per QR module (default 10, ~450px wide)")
    parser.add_argument("--url-template", default=CLAIM_URL,
                        help="link to encode; {token} is replaced "
                             f"(default {CLAIM_URL})")
    parser.add_argument("--dry-run", action="store_true",
                        help="list what would be written")
    args = parser.parse_args(argv)

    if "{token}" not in args.url_template:
        parser.error("--url-template must contain {token}")
    if segno is None and not args.dry_run:
        print("error: needs the segno package: python -m pip install segno",
              file=sys.stderr)
        return 2

    try:
        jobs, skipped = plan(args.csv, args.url_template)
    except (common.PoolError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.dry_run:
        os.makedirs(args.out_dir, exist_ok=True)
    for stem, url in jobs:
        path = os.path.join(args.out_dir, f"{stem}.{args.format}")
        if args.dry_run:
            print(f"  would write {path}\n      {url}")
            continue
        # Error level M with segno's default boost: the level is raised
        # whenever that doesn't grow the symbol.
        segno.make_qr(url, error="m").save(path, scale=args.scale, border=4)
        print(f"  wrote {os.path.relpath(path)}")

    verb = "would write" if args.dry_run else "wrote"
    print(f"\n{verb} {len(jobs)} QR code(s) to {args.out_dir}"
          + (f"; skipped {skipped} row(s) without a claim_token" if skipped else ""))
    return 1 if skipped else 0


if __name__ == "__main__":
    sys.exit(main())
