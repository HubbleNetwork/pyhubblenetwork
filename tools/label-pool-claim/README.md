# claim_tools

Command-line tools for creating Hubble devices, making them claimable, and
printing claim labels.

| Tool | What it does |
|---|---|
| `provision_devices.py` | Register N devices and create a claim for each, in one step |
| `claim_device.py` | Create (or look up) the claim for an existing device, by key, ID or name |
| `make_qr_codes.py` | Save a claim QR code per device, named after the device |
| `print_labels.py` | Render 2" x 1" claim labels and print them on the Zebra ZT411 |
| `activate_devices.py` | Activate devices from a CSV (rarely needed; the claim tools already activate) |

`internal/` is shared code the tools import; `kiosk/` holds the tools for
the smart-label kiosk pool ([kiosk/README.md](kiosk/README.md)).

## Setup

- Python 3.10+. The claim tools are stdlib only; the QR and label tools need
  `python -m pip install segno pillow`.
- Credentials: copy `.env.example` to `.env` and fill it in (see
  [Choosing the org](#choosing-the-org)).

A typical run:

```bash
python provision_devices.py --count 5 --name "nRF52 WorksWith26" --key-size 256 --counter uptime
python print_labels.py keys/nrf52_workswith26_<timestamp>.csv --printer "ZDesigner ZT411-300dpi ZPL"
```

Everything a tool writes (`keys/`, `qr_codes/`, `labels/`) is git-ignored:
it holds device keys and claim tokens.

## provision_devices.py — new devices + claims in one step

```bash
python provision_devices.py                  # asks for anything you leave out
python provision_devices.py --count 5 --name "nRF52 WorksWith26" \
    --key-size 256 --counter uptime
python provision_devices.py ... --dry-run    # show the request, create nothing
```

- `--count` — number of devices (1–1000)
- `--name` — base name; ` 01`, ` 02`, … is appended (`--start 21` to extend a
  batch, `--pad N` to change the zero-padding)
- `--key-size 128|256` — `AES-128-CTR` / `AES-256-CTR`
- `--counter unix|uptime` — `UNIX_TIME` (platform default, left implicit) /
  `DEVICE_UPTIME` (sent as `eid_rotation.counter_source`)

It checks the credentials can read the org, shows a summary and asks to
confirm (`--yes` skips that), registers the devices, **writes the keys to
disk before doing anything else** (the platform never returns a key again),
then creates and links one claim per device. Output is
`keys/<name>_<timestamp>.csv`:

```
device_id,device_name,key,encryption,counter_source,claim_id,claim_token,error
```

**Every claimed device is activated.** Devices are registered
`activated:false`, then each gets `PATCH {"set_activated": true}` right after
its claim is linked, so a device whose claim failed is never left live and
unclaimed. Activation is one-way: the device becomes live and billable.
`--no-activate` claims without activating; `--no-claims` registers and writes
keys only. If a claim fails, the device and key are still in the CSV, and
`python claim_device.py --csv <that file>` finishes it (a claim that was
created but not linked, or linked but not activated, is finished, not
duplicated).

## claim_device.py — claim an existing device

```bash
python claim_device.py <key>                    # base64 as registered, or hex
python claim_device.py <device-uuid>
python claim_device.py "nRF52 WorksWith26 03"   # exact name, case-insensitive
python claim_device.py                          # prompts for one
python claim_device.py --csv keys/batch.csv     # every row missing a claim
```

- **Key** → looked up in `keys/*.csv` (plus any `--csv`). The platform can't be
  searched by key, so it has to be in the CSV written at registration.
- **ID / name** → local CSVs first, then the platform (`GET` the device, or
  the org's device list for a name; a duplicate name is an error that lists
  the IDs).

If a CSV row (including `keys/claims.csv`) already has a claim, it's printed
and nothing is created; `--new` makes a replacement. Otherwise it creates a
claim, links it (`set_device_claim_id` only — name and tags are untouched),
prints `claim_id` / `claim_token`, and writes them back to that CSV row, or
appends them to `keys/claims.csv` for a device that isn't in any CSV. The
device is then activated, including when the claim already existed
(`--no-activate` skips that). `--dry-run` finds the device and shows what it
would do.

The local CSVs are the only record of which claim a device is linked to:
neither the platform's device record nor its claims list says. Keep `keys/`;
without it, `claim_device.py` can't tell a device is already claimed, and a
new claim would orphan the token printed on its label.

## make_qr_codes.py — claim QR codes

```bash
python make_qr_codes.py keys/batch.csv          # -> qr_codes/<device_name>.png
python make_qr_codes.py keys/*.csv --out-dir qr_codes/booth --format svg
```

Each row's `claim_token` is encoded as
`https://dash.hubble.com/claim?claim_token=<token>&type=device` and saved as
`<device_name>.png` (or `.svg`). Characters Windows won't allow in a file name
become `_`, and if two devices share a name the device ID is appended. Rows
with no `claim_token` are listed and skipped (exit code 1).

Codes are generated locally and are static (the link itself is encoded), so
nothing is uploaded and they don't depend on any service.

## print_labels.py — 2" x 1" labels on the Zebra ZT411

```bash
python print_labels.py keys/claims.csv --number "Hubble Dual Stack Battery Test=05"
python print_labels.py --list-printers
python print_labels.py keys/claims.csv --printer "ZDesigner ZT411-300dpi ZPL"
python print_labels.py keys/claims.csv --printer "..." --match "Battery Test"   # just one
python print_labels.py --blank 3 --printer "ZDesigner ZT411-300dpi ZPL"        # feed labels
python print_labels.py keys/claims.csv --host 192.168.1.50                     # over Ethernet
```

Each label has the claim QR code (0.8" square), the device number in large
type, and "Scan Me!". The number is the digits at the end of the device name;
`--number NAME=NN` sets one for a device whose name doesn't end in digits.
Every run writes `labels/<device name>.png` previews and `labels/labels.zpl`.
Labels are rendered at the printer's resolution, so the preview is exactly
what prints: `--dpi`, else read from the queue name, else 203. Our ZT411 is
300 dpi. The space between the text and the label's right end is
`TEXT_RIGHT_EXTRA_IN` at the top of the script.

**USB setup (once):** install Zebra's *ZDesigner* Windows driver for the
ZT411 (zebra.com → Support → ZT411 → Drivers) and plug the printer in. The
queue it creates is named after the model and resolution, e.g.
`ZDesigner ZT411-300dpi ZPL`; `--list-printers` shows it. `--printer` sends
the ZPL through that queue untouched (RAW), so no page scaling applies.

**Media:** calibrate the printer for the 2" x 1" labels (control panel:
Menu → Print → Sensors → calibrate) before the first print. The print method
must match the labels: *Direct Thermal* for labels used without a ribbon.

## activate_devices.py

```bash
python activate_devices.py --csv keys/batch.csv --dry-run
python activate_devices.py --csv keys/batch.csv
```

PATCHes `set_activated: true` for every device in the CSV(s). Only needed
for devices claimed with `--no-activate` or registered some other way.
Activation is one-way (the device becomes live and billable), and
`set_activated` is undocumented: a 403 usually means the org needs a separate
entitlement.

## Choosing the org

Every tool that calls the API loads the `.env` in this folder by default:

```sh
HUBBLE_API_KEY=...        # or HUBBLE_API_TOKEN; bearer token for the org
HUBBLE_ORG_ID=...         # org UUID
HUBBLE_ENDPOINT=https://api.hubble.com   # optional
```

To switch orgs, keep one file per org:

| | |
|---|---|
| `--env customer-x` | use `.env.customer-x` in this folder (the easy way) |
| `--env-file PATH` | a specific file |
| `--org-id UUID` / `--token TOKEN` / `--base-url URL` | override single values on top of whichever file loaded |
| `--no-env-file` | real environment only |

The file wins over the shell environment, including over the other token
variable name: a file with `HUBBLE_API_KEY` isn't shadowed by a
`HUBBLE_API_TOKEN` set in your Windows environment. The tool prints which
file it loaded. `.env` and `.env.*` are git-ignored; `.env.example` is the
template.

The token's org needs the `can_create_device_claims` entitlement and the
`write-devices` scope.

## About claim tokens

Claims are created without a `destination_org_id`, so they are
directionless: whichever org redeems the token (`POST
/device_claims/{claim_id}/claim`) becomes the device's new org. That is the
intended flow — someone scans the QR, signs in, and the device moves to their
org — but it means a printed `claim_token` is bearer-equivalent: anyone
holding it can redeem the device. Treat `keys/`, `qr_codes/` and `labels/`
accordingly.

A claim can be pinned to one org instead, at creation (`POST /device_claims`
with `{"destination_org_id": "<uuid>"}`) or afterwards (`PATCH
/device_claims/{claim_id}` with `{"set_destination_org_id": "<uuid>"}`);
`PlatformClient.create_claim()` in `internal/common.py` is where that would
go.

## Tests

```bash
python -m unittest            # from this folder
```
