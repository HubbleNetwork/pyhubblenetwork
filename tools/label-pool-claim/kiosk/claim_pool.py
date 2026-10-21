#!/usr/bin/env python3
"""Mark a pool of smart labels claimable on the Hubble platform.

Reads a pool.csv of platform device UUIDs, the label name to give each device,
and the box/label numbers printed on each physical label, then for every row:

  1. POST /v1/org/{org}/device_claims          -> claim_id + claim_token
  2. PATCH /v1/org/{org}/devices/{device_id}   -> set_name, set_tags,
                                                  set_device_claim_id

Linking a device to a claim is what makes it claimable. The generated
claim_id / claim_token / device_name are written back into the CSV, which is
the file the smart-label kiosk consumes as its pool.

Rows that already carry a claim_id are not re-claimed, so a re-run resumes
rather than orphaning claims.

Stdlib only. Run from the repo root:

    # HUBBLE_API_TOKEN and HUBBLE_ORG_ID come from .env, or the environment
    python3 kiosk/claim_pool.py --csv pool.csv --dry-run
    python3 kiosk/claim_pool.py --csv pool.csv --limit 1
    python3 kiosk/claim_pool.py --csv pool.csv

Results are written back into --csv, because that is what makes a re-run
resume instead of re-claiming. A <csv>.bak is written before the first write.
"""


from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import sys

# Run as `python kiosk/claim_pool.py`: make the repo root importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from internal import common  # noqa: E402
from internal.common import (  # noqa: E402
    DEFAULT_BASE_URL, ENDPOINT_VARS, NAME_MAX, TOKEN_VARS,
    APIError, Pool, PoolError, PlatformClient, activate_device, apply_dotenv,
    default_dotenv_candidates, field, find_dotenv, new_claim_token,
    write_pool_file,
)

# Platform caps a device at 10 tags total (key <= 32 chars, value <= 128).
MAX_TAGS_PER_DEVICE = 10
TAG_KEY_MAX = 32
TAG_VALUE_MAX = 128

BOX_PAD = 2
LABEL_PAD = 3

REQUIRED_COLUMNS = ("actual_device_id", "box_no", "label_no")


class RowError(Exception):
    """This row is unusable; the rest of the run continues."""



def read_pool(path: str, required=REQUIRED_COLUMNS) -> Pool:
    """common.read_pool, requiring the kiosk pool's box/label columns."""
    return common.read_pool(path, required)


# --------------------------------------------------------------------------
# Naming and tags
# --------------------------------------------------------------------------


def device_name(box_no: str, label_no: str) -> str:
    """Fallback name when the CSV has no name column.

    "Temp Name 01-001" from box 1 / label 1. Longer values are not truncated.
    """
    box = str(box_no).strip()
    label = str(label_no).strip()
    if not box:
        raise RowError("box_no is empty")
    if not label:
        raise RowError("label_no is empty")
    return f"Temp Name {box.zfill(BOX_PAD)}-{label.zfill(LABEL_PAD)}"


def resolve_name(pool: Pool, row: dict) -> str:
    """The label name for this row.

    The CSV is the source of truth: when it has a name column the value is used
    verbatim (whitespace-trimmed only), and a blank cell fails the row rather
    than silently printing a generated name. Only a CSV with no name column at
    all falls back to deriving one from box_no/label_no.
    """
    if "device_name" in pool.colmap:
        name = field(pool, row, "device_name")
        if not name:
            raise RowError("device_name is empty")
        if len(name) > NAME_MAX:
            raise RowError(f"device_name exceeds {NAME_MAX} characters")
        return name
    return device_name(field(pool, row, "box_no"), field(pool, row, "label_no"))


def merge_tags(existing: dict, box_no: str, label_no: str) -> dict:
    """set_tags replaces the whole map, so merge onto what the device has."""
    tags = dict(existing or {})
    tags["box_no"] = str(box_no).strip().zfill(BOX_PAD)
    tags["label_no"] = str(label_no).strip().zfill(LABEL_PAD)

    for key, value in tags.items():
        if len(key) > TAG_KEY_MAX:
            raise RowError(f"tag key {key!r} exceeds {TAG_KEY_MAX} characters")
        if len(str(value)) > TAG_VALUE_MAX:
            raise RowError(f"tag value for {key!r} exceeds {TAG_VALUE_MAX} characters")
    if len(tags) > MAX_TAGS_PER_DEVICE:
        raise RowError(
            f"device would end up with {len(tags)} tags, over the "
            f"{MAX_TAGS_PER_DEVICE} tag limit"
        )
    return tags


# --------------------------------------------------------------------------
# Processing
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Summary:
    claimed: int = 0
    skipped: int = 0
    failed: int = 0
    planned: int = 0
    repaired: int = 0


def process(pool: Pool, client, dry_run: bool = False, limit: int | None = None,
            log=print, activate: bool = True) -> Summary:
    """Claim, name, tag and (by default) activate each row in place. Never
    raises for one bad row. Rows skipped as already claimed are not touched."""
    summary = Summary()
    processed = 0

    for index, row in enumerate(pool.rows, start=1):
        if limit is not None and processed >= limit:
            break

        device_id = field(pool, row, "actual_device_id")
        box_no = field(pool, row, "box_no")
        label_no = field(pool, row, "label_no")
        existing_claim = (row.get("claim_id") or "").strip()
        existing_token = (row.get("claim_token") or "").strip()
        row_error = (row.get("error") or "").strip()

        if not device_id:
            row["error"] = "RowError: actual_device_id is empty"
            summary.failed += 1
            log(f"row {index}: FAILED - actual_device_id is empty")
            continue

        # A row is done only when it has both a claim_id and a claim_token.
        # A claim_id with no token is a claim created before tokens were being
        # supplied: repair it in place rather than creating a second claim.
        if existing_claim and existing_token and not row_error:
            summary.skipped += 1
            log(f"row {index}: skip {device_id} (already claim {existing_claim})")
            continue

        if existing_claim and not existing_token and not dry_run:
            # A repair is a mutation, so it counts against --limit.
            processed += 1
            token = new_claim_token()
            try:
                client.set_claim_token(existing_claim, token)
            except APIError as exc:
                row["error"] = f"APIError: {exc}"
                summary.failed += 1
                log(f"row {index}: FAILED {device_id} - could not backfill token "
                    f"on claim {existing_claim} - {exc}")
                continue
            row["claim_token"] = token
            existing_token = token
            summary.repaired += 1
            log(f"row {index}: repaired {device_id} - set token on claim "
                f"{existing_claim}")
            if not row_error:
                # The device was already named, tagged and linked; only the
                # token was missing.
                if activate:
                    try:
                        activate_device(client, device_id)
                    except APIError as exc:
                        row["error"] = f"APIError: {exc}"
                        summary.failed += 1
                        log(f"row {index}: FAILED {device_id} - {exc}")
                        continue
                row["error"] = ""
                continue

        processed += 1
        try:
            name = resolve_name(pool, row)
            tags = merge_tags(
                (client.get_device(device_id) or {}).get("tags") or {},
                box_no, label_no,
            )
        except RowError as exc:
            row["error"] = f"RowError: {exc}"
            summary.failed += 1
            log(f"row {index}: FAILED {device_id} - {exc}")
            continue
        except APIError as exc:
            row["error"] = f"APIError: {exc}"
            summary.failed += 1
            log(f"row {index}: FAILED {device_id} - {exc}")
            continue

        if dry_run:
            summary.planned += 1
            body = {"set_name": name, "set_tags": tags,
                    "set_device_claim_id": "<new claim>"}
            log(f"row {index}: DRY RUN {device_id}\n"
                f"  POST  device_claims {{\"claim_token\": \"<new uuid4>\"}}\n"
                f"  PATCH devices/{device_id} {json.dumps(body, sort_keys=True)}"
                + (f"\n  PATCH devices/{device_id} {{\"set_activated\": true}}"
                   if activate else ""))
            continue

        claim_id = existing_claim
        claim_token = existing_token
        if not claim_id:
            token = new_claim_token()
            try:
                claim = client.create_claim(claim_token=token)
            except APIError as exc:
                row["claim_id"] = ""
                row["error"] = f"APIError: {exc}"
                summary.failed += 1
                log(f"row {index}: FAILED {device_id} - {exc}")
                continue
            claim_id = claim.get("claim_id", "")
            # The response echoes the token back, but fall back to the one we
            # sent: we know it, and an empty column would strand the label.
            claim_token = claim.get("claim_token") or token

        # Record the claim before linking: if the PATCH fails, the claim
        # exists, and a re-run must link it rather than create another.
        row["claim_id"] = claim_id
        row["claim_token"] = claim_token
        row["device_name"] = name

        try:
            client.patch_device(device_id, {
                "set_name": name,
                "set_tags": tags,
                "set_device_claim_id": claim_id,
            })
        except APIError as exc:
            row["error"] = f"APIError: {exc}"
            summary.failed += 1
            log(f"row {index}: FAILED {device_id} - claim {claim_id} created but "
                f"not linked - {exc}")
            continue

        if activate:
            try:
                activate_device(client, device_id)
            except APIError as exc:
                # Linked; the error makes a re-run re-link (idempotent) and
                # retry the activation.
                row["error"] = f"APIError: {exc}"
                summary.failed += 1
                log(f"row {index}: FAILED {device_id} - {exc}")
                continue

        row["error"] = ""
        summary.claimed += 1
        log(f"row {index}: ok {device_id} -> {name} claim {claim_id}")

    return summary


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def output_path(csv_path: str, out: str | None) -> str:
    """Where the results go. Defaults to the input file.

    Resume works by reading claim_id back out of the pool, so the file written
    must be the file read next time. Writing elsewhere by default meant a
    --limit run's claims were invisible to the next run, which then created a
    second claim for the same device and orphaned the first.
    """
    return out or csv_path


def breaks_resume(csv_path: str, out: str) -> bool:
    return os.path.abspath(csv_path) != os.path.abspath(out)


# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", required=True, help="pool CSV to read")
    parser.add_argument("--org-id", help="source org UUID (env HUBBLE_ORG_ID)")
    parser.add_argument("--base-url", help=f"API base URL (default {DEFAULT_BASE_URL})")
    parser.add_argument("--env-file", help="path to a .env file (default: alongside "
                                           "the script, then ./.env)")
    parser.add_argument("--no-env-file", action="store_true",
                        help="ignore .env entirely; use the real environment only")
    parser.add_argument("--out", help="write results here instead of back into "
                                      "--csv (breaks resume; see --help notes)")
    parser.add_argument("--in-place", action="store_true",
                        help="accepted for compatibility; writing back to --csv "
                             "is the default")
    parser.add_argument("--no-backup", action="store_true",
                        help="skip writing <csv>.bak before the first write")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the requests without calling any write endpoint")
    parser.add_argument("--limit", type=int, help="process at most N unclaimed rows")
    parser.add_argument("--no-activate", action="store_true",
                        help="don't activate claimed devices (activation is "
                             "one-way: the device becomes live and billable)")
    args = parser.parse_args(argv)

    loaded_env = None
    if not args.no_env_file:
        candidates = [args.env_file] if args.env_file else default_dotenv_candidates()
        if args.env_file and not os.path.isfile(args.env_file):
            parser.error(f"--env-file {args.env_file} does not exist")
        loaded_env = apply_dotenv(find_dotenv([c for c in candidates if c]),
                                  os.environ)

    org_id = args.org_id or os.environ.get("HUBBLE_ORG_ID")
    token = next((os.environ[v] for v in TOKEN_VARS if os.environ.get(v)), None)
    base_url = args.base_url
    if not base_url:
        for var in ENDPOINT_VARS:
            if os.environ.get(var):
                base_url = os.environ[var]
                break
    base_url = base_url or DEFAULT_BASE_URL

    if loaded_env:
        print(f"loaded {loaded_env}")
    hint = "" if loaded_env else (
        " (no .env found; looked in "
        + ", ".join(os.path.dirname(c) or "." for c in default_dotenv_candidates())
        + ")")
    if not org_id:
        parser.error(f"--org-id is required, or set HUBBLE_ORG_ID{hint}")
    if not token:
        parser.error("set HUBBLE_API_TOKEN (or HUBBLE_API_KEY) for the source org"
                     + hint)

    try:
        pool = read_pool(args.csv)
    except (PoolError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    client = PlatformClient(base_url, org_id, token)
    print(f"{args.csv}: {len(pool.rows)} row(s), org {org_id}, {base_url}"
          f"{' [DRY RUN]' if args.dry_run else ''}")

    summary = process(pool, client, dry_run=args.dry_run, limit=args.limit,
                      activate=not args.no_activate)

    if args.dry_run:
        print(f"\ndry run: {summary.planned} row(s) would be claimed, "
              f"{summary.skipped} already claimed, {summary.failed} unusable")
        return 1 if summary.failed else 0

    out_path = output_path(args.csv, args.out)
    if breaks_resume(args.csv, out_path) and summary.claimed:
        print(f"\nWARNING: {summary.claimed} claim(s) were created but written to "
              f"{out_path}, not {args.csv}.", file=sys.stderr)
        print("A later run reading --csv will not see them and will create a "
              "second claim per device.", file=sys.stderr)
        print(f"Copy {out_path} over {args.csv} before re-running.",
              file=sys.stderr)

    if not args.no_backup and not os.path.isfile(args.csv + ".bak"):
        try:
            shutil.copy2(args.csv, args.csv + ".bak")
        except OSError as exc:
            print(f"warning: could not write backup: {exc}", file=sys.stderr)

    try:
        write_pool_file(out_path, pool)
    except OSError as exc:
        print(f"error: could not write {out_path}: {exc}", file=sys.stderr)
        print("claims may have been created; recover from the log above",
              file=sys.stderr)
        return 2

    print(f"\nwrote {out_path}")
    print(f"claimed {summary.claimed}, skipped {summary.skipped}, "
          f"repaired {summary.repaired}, failed {summary.failed}")
    if summary.failed:
        print("re-run the same command to retry the failed rows "
              "(claimed rows are skipped)", file=sys.stderr)
    return 1 if summary.failed else 0


if __name__ == "__main__":
    sys.exit(main())
