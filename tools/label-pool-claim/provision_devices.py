#!/usr/bin/env python3
"""Register N devices and create a claim for each, in one step.

For every run:

  1. POST /v2/org/{org}/devices    -> N devices named "<name> 01", "<name> 02", ...
                                      with the chosen key size and EID counter
  2. write the CSV immediately      -> the keys are only ever returned here, so
                                      they hit disk before anything else can fail
  3. per device:
       POST  /v1/org/{org}/device_claims   {"claim_token": <uuid4>}
       PATCH /v1/org/{org}/devices/{id}    {"set_device_claim_id": <claim_id>}
  4. rewrite the CSV with claim_id / claim_token

Anything left out on the command line is asked for interactively:

    python3 provision_devices.py
    python3 provision_devices.py --count 5 --name "nRF52 WorksWith26" \\
        --key-size 256 --counter uptime
    python3 provision_devices.py ... --dry-run     # show the request, change nothing

Output goes to keys/<name>_<timestamp>.csv with columns
device_id,device_name,key,encryption,counter_source,claim_id,claim_token,error.
If some claims fail, the devices and keys are still in the CSV; finish them with

    python3 claim_device.py --csv keys/<that file>.csv

Each device is activated (set_activated:true) right after its claim is
linked, so a device whose claim failed is never left live and unclaimed.
Activation is one-way -- the device becomes live and billable. --no-activate
leaves them inactive (activate_devices.py can do it later).

Org and credentials come from the .env next to this script by default
(HUBBLE_API_TOKEN/HUBBLE_API_KEY, HUBBLE_ORG_ID, optional HUBBLE_ENDPOINT).
--env NAME uses .env.NAME instead; --org-id / --token / --env-file override.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys

from internal import common

KEY_SIZES = {"128": "AES-128-CTR", "256": "AES-256-CTR"}

# UNIX_TIME is the platform default; it is left implicit (as
# the original CC2755/EFR32 batches did) rather than sent explicitly.
COUNTERS = {"unix": "UNIX_TIME", "uptime": "DEVICE_UPTIME"}

MAX_DEVICES = 1000  # per-request cap on POST /v2/org/{org}/devices

COLUMNS = ["device_id", "device_name", "key", "encryption", "counter_source",
           "claim_id", "claim_token", "error"]

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


# --------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------


def device_names(base: str, count: int, start: int = 1,
                 pad: int | None = None) -> list[str]:
    """["nRF52 WorksWith26 01", "nRF52 WorksWith26 02", ...].

    pad defaults to the width of the last number, minimum 2.
    """
    base = base.strip()
    if not base:
        raise ValueError("name is empty")
    last = start + count - 1
    width = pad if pad is not None else max(2, len(str(last)))
    names = [f"{base} {n:0{width}d}" for n in range(start, last + 1)]
    if len(names[-1]) > common.NAME_MAX:
        raise ValueError(f"device names would exceed {common.NAME_MAX} characters")
    return names


def registration_body(names: list[str], encryption: str,
                      counter_source: str) -> dict:
    body: dict = {"n_devices": len(names), "encryption": encryption}
    if counter_source != COUNTERS["unix"]:
        body["eid_rotation"] = {"counter_source": counter_source}
    body["activated"] = False
    body["names"] = names
    return body


def default_output(name: str, now: datetime.datetime | None = None) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "devices"
    stamp = (now or datetime.datetime.now()).strftime("%Y%m%d-%H%M%S")
    return os.path.join(KEYS_DIR, f"{slug}_{stamp}.csv")


def ask(prompt: str, choices: dict | None = None, cast=str):
    """Prompt until a valid answer. Only called when stdin is a terminal."""
    while True:
        answer = common.prompt(prompt)
        if choices is not None:
            if answer.lower() in choices:
                return answer.lower()
            print(f"  choose one of: {', '.join(choices)}")
            continue
        try:
            value = cast(answer)
        except ValueError:
            print("  not a valid value")
            continue
        if value or value == 0:
            return value


def fill_missing(args) -> None:
    """Ask for any required input not given on the command line."""
    missing = [flag for flag, value in (("--count", args.count), ("--name", args.name),
                                        ("--key-size", args.key_size),
                                        ("--counter", args.counter))
               if value is None]
    if not missing:
        return
    if not sys.stdin.isatty():
        raise SystemExit(f"error: missing {', '.join(missing)} (and stdin is not "
                         "a terminal to ask)")
    if args.count is None:
        args.count = ask("How many devices? ", cast=int)
    if args.name is None:
        args.name = ask('Base device name (e.g. "nRF52 WorksWith26"): ')
    if args.key_size is None:
        args.key_size = ask("Key size [128/256]: ", choices=KEY_SIZES)
    if args.counter is None:
        args.counter = ask("EID counter [unix/uptime]: ", choices=COUNTERS)


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------


def rows_from_devices(devices: list[dict], encryption: str,
                      counter_source: str) -> list[dict]:
    return [{
        "device_id": d.get("device_id") or d.get("id") or "",
        "device_name": d.get("name") or "",
        "key": d.get("key") or "",
        "encryption": encryption,
        "counter_source": counter_source,
        "claim_id": "",
        "claim_token": "",
        "error": "",
    } for d in devices]


def claim_row(client, row: dict, activate: bool = True) -> None:
    """Create a claim and link it to the row's device, recording the result
    in the row. Never raises for an API failure; claim_device.py --csv
    finishes any row left with an error."""
    if not row["device_id"]:
        row["error"] = "no device_id in the registration response"
        return
    try:
        common.ensure_claim(client, row["device_id"], row, activate=activate)
    except common.APIError as exc:
        row["error"] = f"APIError: {exc}"


def write_rows(path: str, rows: list[dict]) -> None:
    pool = common.Pool(comments=[], fieldnames=list(COLUMNS), rows=rows, colmap={})
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    common.write_pool_file(path, pool, extra_columns=())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--count", "-n", type=int, help="number of devices")
    parser.add_argument("--name", help='base name; " 01", " 02", ... is appended')
    parser.add_argument("--key-size", choices=sorted(KEY_SIZES),
                        help="128 -> AES-128-CTR, 256 -> AES-256-CTR")
    parser.add_argument("--counter", choices=sorted(COUNTERS),
                        help="EID counter source: unix (UNIX_TIME, platform "
                             "default) or uptime (DEVICE_UPTIME)")
    parser.add_argument("--start", type=int, default=1,
                        help="first number to append (default 1; e.g. 21 to "
                             "extend an existing batch of 20)")
    parser.add_argument("--pad", type=int,
                        help="zero-pad the number to this width (default: width "
                             "of the last number, minimum 2; 1 for no padding)")
    parser.add_argument("--out", help="output CSV (default keys/<name>_<timestamp>.csv)")
    parser.add_argument("--no-activate", action="store_true",
                        help="claim but don't activate (activation is one-way: "
                             "the device becomes live and billable)")
    parser.add_argument("--no-claims", action="store_true",
                        help="register and write keys only; create no claims")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the registration request and change nothing")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="skip the confirmation prompt")
    common.add_org_args(parser)
    args = parser.parse_args(argv)

    fill_missing(args)
    if not 1 <= args.count <= MAX_DEVICES:
        parser.error(f"--count must be between 1 and {MAX_DEVICES}")
    if args.start < 0:
        parser.error("--start must be >= 0")
    try:
        names = device_names(args.name, args.count, start=args.start, pad=args.pad)
    except ValueError as exc:
        parser.error(str(exc))

    org = common.resolve_org(args, parser, need_token=not args.dry_run)
    encryption = KEY_SIZES[args.key_size]
    counter_source = COUNTERS[args.counter]
    body = registration_body(names, encryption, counter_source)
    out = args.out or default_output(args.name)

    if org.loaded_env:
        print(f"loaded {org.loaded_env}")
    print(f"org        {org.org_id} ({org.base_url})")
    print(f"devices    {len(names)}: {names[0]}"
          + (f" .. {names[-1]}" if len(names) > 1 else ""))
    print(f"key        {encryption}")
    print(f"counter    {counter_source}"
          + (" (platform default)" if counter_source == COUNTERS["unix"] else ""))
    print(f"claims     {'no' if args.no_claims else 'yes, one per device'}")
    activate = not (args.no_claims or args.no_activate)
    print(f"activate   {'yes, after each claim is linked (one-way)' if activate else 'no'}")
    print(f"output     {out}")

    client = common.PlatformClient(org.base_url, org.org_id, org.token)
    if org.token:
        try:
            client.check_access()
        except common.APIError as exc:
            print(f"\nerror: these credentials can't read org {org.org_id}: {exc}",
                  file=sys.stderr)
            return 2

    if args.dry_run:
        print(f"\nDRY RUN: would POST {org.base_url.rstrip('/')}/v2/org/"
              f"{org.org_id}/devices")
        print(json.dumps(body, indent=2))
        return 0

    if os.path.exists(out):
        parser.error(f"{out} already exists; pass a different --out")
    if not args.yes:
        if not sys.stdin.isatty():
            parser.error("pass --yes to run non-interactively")
        if common.prompt("\nCreate these devices? [y/N] ").lower() not in ("y", "yes"):
            print("aborted, nothing created")
            return 0

    try:
        devices = client.register_devices(body)
    except common.APIError as exc:
        print(f"\nerror: registration failed: {exc}", file=sys.stderr)
        print("if this was a timeout or 5xx, check the dashboard before "
              "re-running: the devices may have been created anyway",
              file=sys.stderr)
        return 2

    rows = rows_from_devices(devices, encryption, counter_source)
    try:
        write_rows(out, rows)
    except OSError as exc:
        # Last chance to keep the keys: dump them to the terminal.
        print(f"\nerror: could not write {out}: {exc}", file=sys.stderr)
        for row in rows:
            print(",".join(row[c] for c in COLUMNS[:3]), file=sys.stderr)
        return 2
    print(f"\nregistered {len(rows)} device(s); keys written to {out}")
    if len(rows) != len(names):
        print(f"WARNING: asked for {len(names)} devices, got {len(rows)}",
              file=sys.stderr)

    if args.no_claims:
        return 0

    failed = 0
    for row in rows:
        claim_row(client, row, activate=activate)
        if row["error"]:
            failed += 1
            print(f"  FAILED {row['device_name']} - {row['error']}")
        else:
            print(f"  ok {row['device_name']} -> claim {row['claim_id']}"
                  + (", activated" if activate else ""))
        write_rows(out, rows)  # after every device, so a crash loses nothing

    print(f"\nwrote {out}")
    print(f"claimed {len(rows) - failed}, failed {failed}")
    if failed:
        print(f"finish the failed rows with: python3 claim_device.py --csv {out}",
              file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
