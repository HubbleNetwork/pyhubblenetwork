#!/usr/bin/env python3
"""Activate devices listed in one or more CSVs.

Reads the device ID column out of each CSV (any CSV from these tools works)
and PATCHes every device with `set_activated: true`. The claim tools already
activate each device they claim; this is for devices claimed with
--no-activate, or registered some other way.

WARNING -- read before running:

  Per Hubble's own factory-mode documentation, activation is a ONE-WAY DOOR:
  once a device is activated it is considered live (and billable) going
  forward, and this cannot be undone through the API. Only activate devices
  you actually intend to test/deploy now, not your whole reserve pool.

  `set_activated` is also an internal/beta field that Hubble has not put in
  their public API docs (their own engineers called it "the misnamed
  set_activated/de-activated feature. We never documented it"). If this
  403s, your org most likely needs a separate entitlement from the one that
  lets you create devices/claims -- ask Ryan (or whoever admins the org)
  rather than assuming the script or credentials are wrong.

Org and credentials: the .env in this folder by default; --env NAME for
.env.NAME, --org-id / --token / --env-file to override.

Usage:
    python3 activate_devices.py --csv keys/batch.csv --dry-run
    python3 activate_devices.py --csv keys/batch.csv --limit 1
    python3 activate_devices.py --csv keys/a.csv keys/b.csv
"""

from __future__ import annotations

import argparse
import sys

from internal import common


def collect_device_ids(csv_paths: list[str]) -> list[tuple[str, str]]:
    """Read actual_device_id out of each CSV. Returns (csv_path, device_id) pairs.

    Rows with an empty actual_device_id are skipped rather than failing the
    whole run -- an unfilled row just isn't a real device yet.
    """
    pairs: list[tuple[str, str]] = []
    for csv_path in csv_paths:
        pool = common.read_pool(csv_path)
        for row in pool.rows:
            device_id = common.field(pool, row, "actual_device_id")
            if device_id:
                pairs.append((csv_path, device_id))
    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", nargs="+", required=True,
                        help="CSV(s) to read device IDs from")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be PATCHed without calling the API")
    parser.add_argument("--limit", type=int, help="activate at most N devices")
    common.add_org_args(parser)
    args = parser.parse_args(argv)

    org = common.resolve_org(args, parser, need_token=not args.dry_run)
    if org.loaded_env:
        print(f"loaded {org.loaded_env}")
    org_id, token, base_url = org.org_id, org.token, org.base_url
    csv_paths = args.csv

    try:
        pairs = collect_device_ids(csv_paths)
    except (common.PoolError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.limit is not None:
        pairs = pairs[: args.limit]

    print(f"{len(pairs)} device(s) across {len(csv_paths)} file(s) "
          f"({', '.join(csv_paths)}), org {org_id}, {base_url}"
          f"{' [DRY RUN]' if args.dry_run else ''}")

    if not args.dry_run:
        print("\nWARNING: activation is irreversible -- see the top of this script.\n")

    client = common.PlatformClient(base_url, org_id, token or "")
    activated = failed = 0
    for csv_path, device_id in pairs:
        if args.dry_run:
            print(f"  DRY RUN: would PATCH devices/{device_id} "
                  f"{{'set_activated': true}}  (from {csv_path})")
            continue
        try:
            client.patch_device(device_id, {"set_activated": True})
        except common.APIError as exc:
            print(f"  FAILED {device_id} ({csv_path}) - {exc}")
            failed += 1
            continue
        print(f"  activated {device_id} ({csv_path})")
        activated += 1

    if args.dry_run:
        print(f"\ndry run: {len(pairs)} device(s) would be activated")
        return 0

    print(f"\nactivated {activated}, failed {failed}")
    if failed:
        print("re-run to retry the failed devices (activation is idempotent on "
              "the platform side, so re-activating an already-active device is "
              "harmless)", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
