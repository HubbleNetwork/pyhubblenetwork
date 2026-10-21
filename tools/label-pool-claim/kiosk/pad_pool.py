#!/usr/bin/env python3
"""Normalize a pool CSV to zero-padded box and label numbers.

Pads `box_no` to 2 digits and `label_no` to 3, and rewrites the matching
`<box>-<label>` pair inside `device_name` to agree:

    1,1,Hubble Smart Label 1-1     ->  01,001,Hubble Smart Label 01-001

Padded values are what claim_pool.py writes into the device tags, so running
this first keeps the CSV, the printed label name, and the platform tags all in
agreement. It is idempotent, so it is safe to run on every new box.

Refuses to touch a pool whose rows already carry a claim_id: those names are
already live on the platform, and renaming them here would silently diverge
from what was provisioned. Use --force if you have decided otherwise.

Usage:
    python3 kiosk/pad_pool.py --csv pool.csv --dry-run
    python3 kiosk/pad_pool.py --csv pool.csv
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys

# Run as `python kiosk/pad_pool.py`: make the repo root importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kiosk import claim_pool as cp  # noqa: E402

# The trailing "<box>-<label>" pair in a device name, with optional spaces.
NAME_PAIR = re.compile(r"(?P<box>\d+)\s*-\s*(?P<label>\d+)\s*$")


class PadError(Exception):
    """The pool cannot be padded safely."""


def pad_name(name: str, box_no: str, label_no: str) -> str:
    """Pad the trailing number pair in `name` to match the padded columns.

    A name with no trailing pair is returned unchanged. A name whose pair
    disagrees with box_no/label_no raises, rather than being rewritten to
    something the operator did not intend.
    """
    name = name.strip()
    match = NAME_PAIR.search(name)
    if not match:
        return name

    box, label = box_no.strip(), label_no.strip()
    if int(match.group("box")) != int(box) or int(match.group("label")) != int(label):
        raise PadError(
            f"name {name!r} and columns (box {box}, label {label}) disagree; "
            "fix the row by hand"
        )

    padded = f"{box.zfill(cp.BOX_PAD)}-{label.zfill(cp.LABEL_PAD)}"
    return name[: match.start()] + padded


def pad_pool(pool: cp.Pool) -> int:
    """Pad every row in place. Returns the number of rows changed.

    All-or-nothing: a single bad row raises and leaves the pool untouched.
    """
    box_col = pool.colmap["box_no"]
    label_col = pool.colmap["label_no"]
    name_col = pool.colmap.get("device_name")

    staged: list[tuple[dict, dict[str, str]]] = []
    for index, row in enumerate(pool.rows, start=1):
        box = cp.field(pool, row, "box_no")
        label = cp.field(pool, row, "label_no")
        if not box or not label:
            raise PadError(f"row {index}: box_no or label_no is empty")

        update = {
            box_col: box.zfill(cp.BOX_PAD),
            label_col: label.zfill(cp.LABEL_PAD),
        }
        if name_col:
            name = cp.field(pool, row, "device_name")
            if name:
                try:
                    update[name_col] = pad_name(name, box, label)
                except PadError as exc:
                    raise PadError(f"row {index}: {exc}") from None
        staged.append((row, update))

    changed = 0
    for row, update in staged:
        if any(row.get(key) != value for key, value in update.items()):
            changed += 1
        row.update(update)
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", required=True, help="pool CSV to normalize in place")
    parser.add_argument("--dry-run", action="store_true",
                        help="show what would change and write nothing")
    parser.add_argument("--force", action="store_true",
                        help="pad even if rows already carry a claim_id")
    parser.add_argument("--no-backup", action="store_true",
                        help="skip writing <csv>.bak")
    args = parser.parse_args(argv)

    try:
        pool = cp.read_pool(args.csv)
    except (cp.PoolError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    claimed = [i for i, r in enumerate(pool.rows, start=1)
               if (r.get("claim_id") or "").strip()]
    if claimed and not args.force:
        print(f"error: {len(claimed)} row(s) already have a claim_id "
              f"(first: row {claimed[0]}).", file=sys.stderr)
        print("Those devices are already named on the platform; padding the CSV "
              "now would diverge from what was provisioned.", file=sys.stderr)
        print("Re-run with --force only if you intend to re-patch them.",
              file=sys.stderr)
        return 2

    before = [(cp.field(pool, r, "box_no"), cp.field(pool, r, "label_no"),
               cp.field(pool, r, "device_name")) for r in pool.rows]

    try:
        changed = pad_pool(pool)
    except PadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("nothing was written", file=sys.stderr)
        return 2

    shown = 0
    for old, row in zip(before, pool.rows):
        new = (cp.field(pool, row, "box_no"), cp.field(pool, row, "label_no"),
               cp.field(pool, row, "device_name"))
        if old != new and shown < 5:
            print(f"  {old[0]},{old[1]},{old[2]}  ->  {new[0]},{new[1]},{new[2]}")
            shown += 1
    if changed > shown:
        print(f"  ... and {changed - shown} more")

    if args.dry_run:
        print(f"\ndry run: {changed} of {len(pool.rows)} row(s) would change")
        return 0

    if not changed:
        print(f"{args.csv}: already padded, nothing to do")
        return 0

    if not args.no_backup:
        backup = args.csv + ".bak"
        shutil.copy2(args.csv, backup)
        print(f"\nbacked up {os.path.basename(args.csv)} -> "
              f"{os.path.basename(backup)}")

    try:
        # extra_columns=() so padding never changes the file's column set.
        cp.write_pool_file(args.csv, pool, extra_columns=())
    except OSError as exc:
        print(f"error: could not write {args.csv}: {exc}", file=sys.stderr)
        return 2

    print(f"padded {changed} of {len(pool.rows)} row(s) in {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
