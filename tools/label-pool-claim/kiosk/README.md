# kiosk/ — smart-label kiosk pool

Tools for the smart-label kiosk flow (`smart-label-kiosk/data/pool.csv`):
`claim_pool.py` marks a pool of labels claimable, names and tags each device
with its box/label numbers, and writes the claim tokens back into the pool
CSV the kiosk prints from. `pad_pool.py` normalizes that CSV first.

For new devices outside the kiosk flow, use `provision_devices.py` and
`claim_device.py` at the repo root instead. Run these from the repo root:

```bash
python kiosk/pad_pool.py --csv pool.csv            # zero-pad box/label/name
python kiosk/claim_pool.py --csv pool.csv --dry-run
python kiosk/claim_pool.py --csv pool.csv --limit 1
python kiosk/claim_pool.py --csv pool.csv
```

Credentials and org selection work as for the other tools (the repo's
`.env`, `--env-file`, `--org-id`); see the root README. `pool.example.csv`
shows the input format.

## Input

A CSV with these columns. Header matching is case-insensitive; `box`/`label`,
`box_number`/`label_number` and `label_name`/`name` are also accepted. Leading
`#` comment lines are preserved.

```csv
# Box 01 of demo smart labels
actual_device_id,box_no,label_no,device_name
11111111-1111-4111-8111-111111111111,1,1,Booth Label A
```

- `actual_device_id` — the **platform device UUID**. Required.
- `box_no`, `label_no` — the numbers printed on the physical label. Required;
  they become the device tags.
- `device_name` — the label name to set. Used **verbatim** (whitespace-trimmed
  only); nothing is padded or reformatted. A blank cell fails that row rather
  than printing a generated name.

`device_name` is optional as a column: a CSV without it falls back to deriving
`Temp Name 01-001` from `box_no`/`label_no`.

## Normalizing first: pad_pool.py

`claim_pool.py` writes **padded** values into the device tags (`box_no=01`,
`label_no=001`), so the CSV should be padded to match. `pad_pool.py` does that:

```bash
python kiosk/pad_pool.py --csv pool.csv --dry-run   # show the changes
python kiosk/pad_pool.py --csv pool.csv             # apply, writing pool.csv.bak
```

It pads `box_no` to 2 digits, `label_no` to 3, and the trailing `<box>-<label>`
pair inside `device_name` so all three agree:

```
1,1,Hubble Smart Label 1-1   ->   01,001,Hubble Smart Label 01-001
```

It is idempotent, so run it on every new box. It never changes the file's
column set, and it is all-or-nothing: a name whose embedded numbers disagree
with its columns aborts the run untouched rather than being rewritten to
something you did not intend.

It refuses to pad a pool whose rows already carry a `claim_id` — those devices
are already named on the platform, so padding the CSV afterwards would diverge
from what was provisioned. Pad *before* claiming. (`--force` overrides, but
then you also need to re-run `claim_pool.py` to re-patch the names.)

## What it does per row

1. `POST /v1/org/{org}/device_claims` with a **script-generated**
   `{"claim_token": "<uuid4>"}`. One claim per device.

   The platform generates the `claim_id` but **not** the `claim_token`: that
   field is caller-supplied, and a claim created without one comes back with it
   empty and can only be redeemed by `claim_id`. The kiosk QR carries a
   `claim_token`, so the script always supplies one. The token written to the
   CSV is the one sent, not the one echoed back, so an omitted field in the
   response cannot strand a label.
2. `GET /v1/org/{org}/devices/{id}` — reads existing tags, because `set_tags`
   replaces the whole map and `_env` must survive.
3. `PATCH /v1/org/{org}/devices/{id}` in one call:
   - `set_name`: the `device_name` from the CSV (max 250 chars)
   - `set_tags`: existing tags + `box_no` + `label_no`
   - `set_device_claim_id`: the new claim — **this is what makes it claimable**
4. `PATCH /v1/org/{org}/devices/{id}` with `{"set_activated": true}`, sent on
   its own as `activate_devices.py` does. This is one-way (the device goes live
   and billable); `--no-activate` skips it. Only rows claimed in this run are
   activated; rows skipped as already claimed aren't touched. If activation
   fails, the row keeps its claim and gets an error, and a re-run re-links
   (idempotent) and retries rather than creating a second claim.

## Output

Adds `claim_id`, `claim_token`, `error` columns, and `device_name` if the
input didn't already have it (an existing column is reused, not duplicated).
Results are written back into `--csv` (a `<csv>.bak` copy is made first), via
a temp file and rename; that write-back is what lets a re-run resume.

## Resuming

A row is considered done only when it has **both** a `claim_id` and a
`claim_token`. A row with a `claim_id` but an empty `claim_token` is a claim
created without a token: the script backfills one via
`PATCH /device_claims/{claim_id}` with `set_claim_token` rather than creating a
second claim (reported as `repaired`). A row with a `claim_id` and no `error`
and a token is skipped. A row with a `claim_id` *and*
an `error` is a claim that was created but never linked — a re-run links the
existing claim rather than creating a second one. So the recovery for any
failure is: re-run the same command.

Exit codes: `0` clean, `1` some rows failed, `2` could not start / could not write.

## Requirements

The token's org needs the `can_create_device_claims` entitlement and the
`write-devices` scope.
