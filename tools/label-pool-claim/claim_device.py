#!/usr/bin/env python3
"""Create (or look up) the claim for an existing device.

Pass whatever you have for the device -- its key, its device ID, or its exact
name -- and it is figured out:

    python3 claim_device.py <key>              # base64 as registered, or hex
    python3 claim_device.py <device-uuid>
    python3 claim_device.py "nRF52 WorksWith26 03"
    python3 claim_device.py <a> <b> <c>        # several at once

    python3 claim_device.py --csv keys/batch.csv   # every row still missing a claim

Lookup order:

  key   -> the CSVs in keys/ (plus any --csv). The platform only returns a
           key at registration and cannot be searched by it, so a key has to
           be in a CSV written when the device was registered (provision_devices.py).
  id    -> local CSVs, then GET /v1/org/{org}/devices/{id}
  name  -> local CSVs, then the org's device list (exact, case-insensitive;
           more than one match is an error, listing the IDs)

If the device's CSV row already has a claim, that claim is printed and
nothing is created (--new creates a fresh one). Otherwise:

    POST  /v1/org/{org}/device_claims   {"claim_token": <uuid4>}
    PATCH /v1/org/{org}/devices/{id}    {"set_device_claim_id": <claim_id>}

Either way the device is then activated (PATCH {"set_activated": true}).
That is one-way -- the device becomes live and billable -- and --no-activate
skips it. (--csv with no device given only touches rows missing a claim.)

and the claim is written back to that CSV row, or appended to
keys/claims.csv for a device that isn't in any CSV.

Org and credentials: same as provision_devices.py -- the .env next to this
script by default, --env NAME for .env.NAME, --org-id/--token/--env-file to
override.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import dataclasses
import datetime
import glob
import os
import re
import sys

from internal import common

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(HERE, "keys")
ADHOC_LOG = os.path.join(KEYS_DIR, "claims.csv")
ADHOC_COLUMNS = ["created", "device_id", "device_name", "claim_id", "claim_token"]

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                     re.IGNORECASE)
HEX_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{64})$", re.IGNORECASE)


class NotFound(Exception):
    """The device could not be identified."""


# --------------------------------------------------------------------------
# Classifying the query
# --------------------------------------------------------------------------


def as_key(text: str) -> str | None:
    """The base64 form of `text` if it looks like a 128/256-bit key, else None.

    Hex (32 or 64 digits, optional 0x / spaces / colons) is converted to
    base64, since that is how the key is stored in the CSV.
    """
    compact = re.sub(r"[\s:]", "", text)
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if HEX_RE.match(compact):
        return base64.b64encode(bytes.fromhex(compact)).decode()
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    return compact if len(raw) in (16, 32) else None


def classify(query: str) -> tuple[str, str]:
    """("id" | "key" | "name", normalized value)."""
    query = query.strip()
    if UUID_RE.match(query):
        return "id", query.lower()
    key = as_key(query)
    if key:
        return "key", key
    return "name", query


# --------------------------------------------------------------------------
# Local CSVs
# --------------------------------------------------------------------------


@dataclasses.dataclass
class LocalRow:
    path: str
    pool: common.Pool
    row: dict

    @property
    def device_id(self) -> str:
        return common.field(self.pool, self.row, "actual_device_id")

    @property
    def name(self) -> str:
        return common.field(self.pool, self.row, "device_name")


def default_csvs() -> list[str]:
    return sorted(glob.glob(os.path.join(KEYS_DIR, "*.csv")))


def load_local(paths: list[str], log=print) -> list[LocalRow]:
    rows: list[LocalRow] = []
    seen: set[str] = set()
    for path in paths:
        full = os.path.abspath(path)
        if full in seen:
            continue
        seen.add(full)
        try:
            pool = common.read_pool(path, required=("actual_device_id",))
        except (common.PoolError, OSError) as exc:
            log(f"  (skipping {path}: {exc})")
            continue
        rows.extend(LocalRow(path, pool, row) for row in pool.rows)
    return rows


def match_local(rows: list[LocalRow], kind: str, value: str) -> list[LocalRow]:
    if kind == "id":
        hits = [r for r in rows if r.device_id.lower() == value]
    elif kind == "key":
        hits = [r for r in rows if common.field(r.pool, r.row, "key") == value]
    else:
        hits = [r for r in rows if r.name.casefold() == value.casefold()]
    # The same device can appear more than once (a copied pool, or older
    # rows in keys/claims.csv); the last row is the most recent claim.
    unique: dict[str, LocalRow] = {}
    for hit in hits:
        unique[hit.device_id.lower()] = hit
    return list(unique.values())


# --------------------------------------------------------------------------
# Resolving one query
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Target:
    device_id: str
    name: str
    local: LocalRow | None


def resolve(query: str, rows: list[LocalRow], client, searched: list[str],
            platform_devices=None) -> Target:
    kind, value = classify(query)

    hits = match_local(rows, kind, value)
    if len(hits) > 1:
        raise NotFound(f"{query!r} matches {len(hits)} devices in local CSVs: "
                           + ", ".join(f"{h.device_id} ({h.path})" for h in hits))
    if hits:
        return Target(hits[0].device_id, hits[0].name, hits[0])

    if kind == "key":
        raise NotFound(
            f"key not found in {len(searched)} local CSV(s) "
            f"({', '.join(os.path.basename(p) for p in searched) or 'none'}). "
            "The platform only returns keys at registration and can't be "
            "searched by key -- pass the device ID or name instead, or point "
            "--csv at the file the key came from.")

    if kind == "id":
        device = client.get_device(value)
        return Target(value, device.get("name") or "", None)

    devices = platform_devices() if platform_devices else list(client.list_devices())
    named = [d for d in devices if (d.get("name") or "").casefold() == value.casefold()]
    if not named:
        raise NotFound(f"no device named {value!r} in the org "
                           f"({len(devices)} device(s) searched)")
    if len(named) > 1:
        raise NotFound(f"{len(named)} devices are named {value!r}; pass one of "
                           "these IDs instead: "
                           + ", ".join(d.get("id") or d.get("device_id") or "?"
                                       for d in named))
    device = named[0]
    return Target(device.get("id") or device.get("device_id"), device.get("name"), None)


# --------------------------------------------------------------------------
# Writing results
# --------------------------------------------------------------------------


def append_adhoc(target: Target, row: dict, path: str | None = None) -> None:
    path = path or ADHOC_LOG
    os.makedirs(os.path.dirname(path), exist_ok=True)
    new_file = not os.path.isfile(path)
    fieldnames = ADHOC_COLUMNS
    if not new_file:
        # Match the existing header, which gains an error column if a row
        # was ever rewritten in place.
        with open(path, newline="", encoding="utf-8") as fh:
            fieldnames = next(csv.reader(fh), None) or ADHOC_COLUMNS
    with open(path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore",
                                restval="")
        if new_file:
            writer.writeheader()
        writer.writerow({
            "created": datetime.datetime.now().isoformat(timespec="seconds"),
            "device_id": target.device_id,
            "device_name": target.name,
            "claim_id": row.get("claim_id", ""),
            "claim_token": row.get("claim_token", ""),
        })


def claim(target: Target, row: dict, client, new: bool, dry_run: bool,
          activate: bool = True, log=print) -> str:
    """Ensure `target` has a claim (and, by default, is activated), recording
    it in `row`. Returns what was done ("existing", "created", ...), or ""
    for a dry run."""
    has_claim = bool((row.get("claim_id") or "").strip()
                     and (row.get("claim_token") or "").strip()
                     and not (row.get("error") or "").strip())

    if has_claim and not new:
        log("  already claimed (from local CSV; --new to replace)")
        if activate and not dry_run:
            common.activate_device(client, target.device_id)
            log("  activated")
        elif activate:
            log(f"  DRY RUN: would PATCH devices/{target.device_id} "
                '{"set_activated": true}')
        return "existing"

    # Neither the device record nor the claims list says which claim a
    # device is linked to, so the local CSVs (keys/*.csv, including
    # claims.csv) are the only record that a device is already claimed.

    if dry_run:
        log("  DRY RUN: would POST device_claims and PATCH "
            f"devices/{target.device_id} {{\"set_device_claim_id\": <new claim>}}"
            + (", then {\"set_activated\": true}" if activate else ""))
        return ""

    action = common.ensure_claim(client, target.device_id, row, new=new,
                             activate=activate)
    log(f"  {action} claim" + (", activated" if activate else ""))
    return action


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("device", nargs="*",
                        help="device key (base64 or hex), device ID, or exact name")
    parser.add_argument("--csv", nargs="+", default=[],
                        help="extra CSV(s) to search; with no device given, claim "
                             "every row in them that doesn't have a claim yet")
    parser.add_argument("--new", action="store_true",
                        help="create a new claim even if one is already recorded")
    parser.add_argument("--dry-run", action="store_true",
                        help="find the device(s) and show what would happen")
    parser.add_argument("--no-activate", action="store_true",
                        help="claim but don't activate (activation is one-way: "
                             "the device becomes live and billable)")
    common.add_org_args(parser)
    args = parser.parse_args(argv)

    if not args.device and not args.csv:
        if sys.stdin.isatty():
            answer = common.prompt("Device key, ID, or name: ")
            if not answer:
                return 0
            args.device = [answer]
        else:
            parser.error("give a device key, ID or name, or --csv")

    org = common.resolve_org(args, parser)
    if org.loaded_env:
        print(f"loaded {org.loaded_env}")
    print(f"org {org.org_id} ({org.base_url}){' [DRY RUN]' if args.dry_run else ''}")
    client = common.PlatformClient(org.base_url, org.org_id, org.token)

    searched = default_csvs() + list(args.csv)
    rows = load_local(searched)

    if args.device:
        cache: list[dict] = []

        def platform_devices() -> list[dict]:
            if not cache:
                print("  searching the org's device list...")
                cache.extend(client.list_devices())
            return cache

        targets = []
        for query in args.device:
            try:
                targets.append(resolve(query, rows, client, searched, platform_devices))
            except (NotFound, common.APIError) as exc:
                print(f"\n{query}\n  FAILED - {exc}")
                targets.append(None)
    else:
        csv_paths = {os.path.abspath(p) for p in args.csv}
        targets = [Target(r.device_id, r.name, r) for r in rows
                   if os.path.abspath(r.path) in csv_paths and r.device_id
                   and not ((r.row.get("claim_id") or "").strip()
                            and (r.row.get("claim_token") or "").strip()
                            and not (r.row.get("error") or "").strip())]
        print(f"{len(targets)} row(s) without a claim in {', '.join(args.csv)}")

    failed = sum(1 for t in targets if t is None)
    dirty: dict[str, common.Pool] = {}
    for target in targets:
        if target is None:
            continue
        print(f"\n{target.name or '(unnamed)'}  {target.device_id}"
              + (f"  [{os.path.basename(target.local.path)}]" if target.local else ""))
        row = target.local.row if target.local else {}
        try:
            action = claim(target, row, client, args.new, args.dry_run,
                           activate=not args.no_activate)
        except (NotFound, common.APIError) as exc:
            print(f"  FAILED - {exc}")
            failed += 1
            if isinstance(exc, common.APIError):
                row["error"] = f"APIError: {exc}"
            action = "unlinked" if row.get("claim_id") else ""
            if target.local:
                dirty[target.local.path] = target.local.pool
            if not action:
                continue
            if isinstance(exc, common.ActivationError):
                print("  the claim below is linked but the device is NOT activated"
                      "; re-run the same command to retry")
            else:
                print("  the claim below exists but is NOT linked to the device"
                      + ("; re-run the same command to link it" if target.local else ""))
        if not action:
            continue
        print(f"  claim_id     {row.get('claim_id', '')}")
        print(f"  claim_token  {row.get('claim_token', '')}")
        if action == "existing":
            continue
        if target.local:
            dirty[target.local.path] = target.local.pool
        else:
            append_adhoc(target, row)
            print(f"  recorded in {os.path.relpath(ADHOC_LOG)}")

    for path, pool in dirty.items():
        try:
            common.write_pool_file(path, pool)
            print(f"\nupdated {path}")
        except OSError as exc:
            print(f"\nerror: could not write {path}: {exc} -- the claims above "
                  "exist; copy them from this output", file=sys.stderr)
            return 2

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
