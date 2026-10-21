"""Shared plumbing for the claim tools. Not meant to be run directly.

  - .env / org selection (the .env next to the tools wins over the shell)
  - PlatformClient: the Hubble API calls the tools make
  - reading and writing device CSVs
  - creating, linking and activating claims
  - the claim link a QR code encodes
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

# The repo root: .env files and keys/ live there, not in internal/.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_BASE_URL = "https://api.hubble.com"

# Read from a .env file next to the script / in the working directory. The
# file wins over whatever is already set in the real environment, so a
# permanent personal-org token/org-id in your shell profile doesn't silently
# shadow the .env this pool is meant to use. HUBBLE_ENDPOINT is the name used
# by the sibling hubble-org-provision project; HUBBLE_API_BASE_URL is also
# accepted.
ENDPOINT_VARS = ("HUBBLE_ENDPOINT", "HUBBLE_API_BASE_URL")
TOKEN_VARS = ("HUBBLE_API_TOKEN", "HUBBLE_API_KEY")

# set_name is capped at 250 characters by the platform.
NAME_MAX = 250

# Output columns appended to whatever the input CSV already had.
OUTPUT_COLUMNS = ["device_name", "claim_id", "claim_token", "error"]

# Input header aliases, normalized lowercase. First match wins.
HEADER_ALIASES = {
    "actual_device_id": ("actual_device_id", "actualdeviceid", "device_id", "deviceid"),
    "box_no": ("box_no", "boxno", "box", "box_number", "box#"),
    "label_no": ("label_no", "labelno", "label", "label_number", "label#"),
    # Optional. When absent, the name is derived from box_no/label_no.
    "device_name": ("device_name", "devicename", "label_name", "labelname",
                    "name", "temp_name"),
    # Optional. The device encryption key, as written at registration.
    "key": ("key", "device_key", "encryption_key"),
}

# Every tool needs a device ID; the kiosk pool also needs box/label numbers.
REQUIRED_COLUMNS = ("actual_device_id",)

CLAIM_URL = "https://dash.hubble.com/claim?claim_token={token}&type=device"

# Characters Windows won't allow in a file name, plus control characters.
UNSAFE_FILENAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


class PoolError(Exception):
    """The CSV itself is unusable."""


class APIError(Exception):
    """A platform API call failed."""


class ActivationError(APIError):
    """The claim is linked but set_activated failed."""



# --------------------------------------------------------------------------
# .env
# --------------------------------------------------------------------------


def parse_dotenv(path: str) -> dict[str, str]:
    """Parse a KEY=VALUE .env file. Malformed lines are ignored, not fatal."""
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, sep, value = line.partition("=")
            key = key.strip()
            if not sep or not key:
                continue
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key] = value
    return values


def find_dotenv(candidates: list[str]) -> str | None:
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def default_dotenv_candidates() -> list[str]:
    """The repo root, then the working directory, then one level up."""
    return [
        os.path.join(ROOT, ".env"),
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(ROOT), ".env"),
    ]


def apply_dotenv(path: str | None, environ) -> str | None:
    """Load the .env file into `environ`. The file wins over the real
    environment: a key already set there is overwritten by the file's value,
    so a permanent personal-org token/org-id in your shell profile can't
    silently shadow the .env this pool is meant to use.

    Returns the path actually loaded, or None.
    """
    if not path or not os.path.isfile(path):
        return None
    values = parse_dotenv(path)
    # "The file wins" has to cover aliases too: a file that sets
    # HUBBLE_API_KEY must not lose to a HUBBLE_API_TOKEN left in the shell,
    # which is checked first. Drop the other aliases the file didn't set.
    for group in (TOKEN_VARS, ENDPOINT_VARS):
        if any(var in values for var in group):
            for var in group:
                if var not in values:
                    environ.pop(var, None)
    for key, value in values.items():
        environ[key] = value
    return path


@dataclasses.dataclass
class OrgConfig:
    org_id: str
    token: str
    base_url: str
    loaded_env: str | None


def prompt(text: str) -> str:
    """input() that exits cleanly when there is nobody to answer (stdin
    closed or redirected; on Windows NUL still claims to be a terminal)."""
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit("aborted: no input (pass the values as flags to run "
                         "non-interactively)")


def add_org_args(parser: argparse.ArgumentParser) -> None:
    """The org/credential flags shared by provision_devices.py and
    claim_device.py. With none of them, the .env next to the script is used."""
    group = parser.add_argument_group(
        "org / credentials (default: the .env next to this script)")
    group.add_argument("--env", metavar="NAME",
                       help="use .env.NAME next to the script instead of .env "
                            "(one file per org, e.g. --env customer-x)")
    group.add_argument("--env-file", help="path to a specific .env file")
    group.add_argument("--no-env-file", action="store_true",
                       help="ignore .env files; use the real environment only")
    group.add_argument("--org-id", help="org UUID (overrides HUBBLE_ORG_ID)")
    group.add_argument("--token", help="API token (overrides HUBBLE_API_TOKEN/"
                                       "HUBBLE_API_KEY; prefer a .env file so it "
                                       "stays out of shell history)")
    group.add_argument("--base-url", help=f"API base URL (default {DEFAULT_BASE_URL})")


def resolve_org(args, parser: argparse.ArgumentParser,
                need_token: bool = True) -> OrgConfig:
    """Load the .env file (it wins over the real environment, as everywhere
    in this repo), then let explicit flags win over both."""
    env_file = args.env_file
    if args.env:
        env_file = os.path.join(ROOT, f".env.{args.env}")
    if env_file and not os.path.isfile(env_file):
        parser.error(f"{env_file} does not exist")

    loaded_env = None
    if not args.no_env_file:
        candidates = [env_file] if env_file else default_dotenv_candidates()
        loaded_env = apply_dotenv(find_dotenv(candidates), os.environ)

    org_id = args.org_id or os.environ.get("HUBBLE_ORG_ID")
    token = args.token or next(
        (os.environ[v] for v in TOKEN_VARS if os.environ.get(v)), None)
    base_url = args.base_url or next(
        (os.environ[v] for v in ENDPOINT_VARS if os.environ.get(v)), None)

    hint = f" (loaded {loaded_env})" if loaded_env else (
        " (no .env found; looked in "
        + ", ".join(os.path.dirname(c) or "." for c in default_dotenv_candidates())
        + ")")
    if not org_id:
        parser.error(f"--org-id is required, or set HUBBLE_ORG_ID{hint}")
    if need_token and not token:
        parser.error(f"set HUBBLE_API_TOKEN (or HUBBLE_API_KEY), or pass --token{hint}")
    return OrgConfig(org_id=org_id, token=token or "",
                     base_url=base_url or DEFAULT_BASE_URL, loaded_env=loaded_env)


# --------------------------------------------------------------------------
# CSV
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Pool:
    comments: list[str]
    fieldnames: list[str]
    rows: list[dict]
    colmap: dict[str, str]


def _normalize(header: str) -> str:
    return header.strip().lower().replace(" ", "_").replace("-", "_")


def _build_colmap(fieldnames: list[str],
                  required=REQUIRED_COLUMNS) -> dict[str, str]:
    """Map each logical column to the actual header used in this file."""
    normalized = {_normalize(f): f for f in fieldnames if f}
    colmap: dict[str, str] = {}
    for logical, aliases in HEADER_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                colmap[logical] = normalized[alias]
                break
    missing = [c for c in required if c not in colmap]
    if missing:
        raise PoolError(
            f"pool CSV is missing required column(s): {', '.join(missing)}; "
            f"saw headers: {', '.join(f for f in fieldnames if f)}"
        )
    return colmap


def read_pool(path: str, required=REQUIRED_COLUMNS) -> Pool:
    """Read a device CSV, preserving leading '#' comment lines verbatim.

    `required` names the logical columns that must be present;
    kiosk/claim_pool.py also requires box_no/label_no.
    """
    with open(path, newline="", encoding="utf-8") as fh:
        raw = fh.read()

    comments: list[str] = []
    body_lines: list[str] = []
    in_body = False
    for line in raw.splitlines():
        if not in_body and (line.startswith("#") or not line.strip()):
            if line.startswith("#"):
                comments.append(line)
            continue
        in_body = True
        body_lines.append(line)

    if not body_lines:
        raise PoolError(f"{path}: no CSV header row found")

    reader = csv.DictReader(body_lines)
    fieldnames = list(reader.fieldnames or [])
    colmap = _build_colmap(fieldnames, required)
    rows = [dict(r) for r in reader]
    return Pool(comments=comments, fieldnames=fieldnames, rows=rows, colmap=colmap)


def field(pool: Pool, row: dict, logical: str) -> str:
    """Read a logical column from a row, whatever the file called it."""
    value = row.get(pool.colmap.get(logical, logical)) or ""
    return value.strip()


def write_pool(handle, pool: Pool, extra_columns=OUTPUT_COLUMNS) -> None:
    """Write comments then the CSV body.

    `extra_columns` are appended if the input did not already have them; pass
    an empty tuple to preserve the input's exact column set (pad_pool does,
    since a normalizer should not change the shape of the file).
    """
    for comment in pool.comments:
        handle.write(comment + "\n")

    fieldnames = list(pool.fieldnames)
    for column in extra_columns:
        if column not in fieldnames:
            fieldnames.append(column)

    writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in pool.rows:
        writer.writerow({key: row.get(key, "") for key in fieldnames})


def write_pool_file(path: str, pool: Pool, extra_columns=OUTPUT_COLUMNS) -> None:
    """Write via a temp file and rename, so a crash can't shred the pool."""
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        write_pool(fh, pool, extra_columns=extra_columns)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Platform API
# --------------------------------------------------------------------------


class PlatformClient:
    def __init__(self, base_url: str, org_id: str, token: str, timeout: float = 30.0,
                 retries: int = 3):
        self.base_url = base_url.rstrip("/")
        self.org_id = org_id
        self.token = token
        self.timeout = timeout
        self.retries = retries

    def _url(self, suffix: str) -> str:
        return f"{self.base_url}/v1/org/{self.org_id}/{suffix.lstrip('/')}"

    def _send(self, method: str, url: str, body: dict | None = None,
              retry: bool = True) -> dict:
        return self._request(method, url, body, retry=retry)[0]

    def _request(self, method: str, url: str, body: dict | None = None,
                 headers: dict | None = None, retry: bool = True) -> tuple[dict, dict]:
        """Send one request. Returns (json body, response headers).

        retry=False is for calls that are not idempotent (device registration):
        a 5xx there may still have created the devices, so retrying could
        register a second batch.
        """
        payload = None if body is None else json.dumps(body).encode()
        last: Exception | None = None
        attempts = self.retries if retry else 1
        for attempt in range(attempts):
            request = urllib.request.Request(url, data=payload, method=method)
            request.add_header("Authorization", f"Bearer {self.token}")
            request.add_header("Accept", "application/json")
            if payload is not None:
                request.add_header("Content-Type", "application/json")
            for key, value in (headers or {}).items():
                request.add_header(key, value)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    text = response.read().decode() or "{}"
                    response_headers = dict(response.headers.items())
                return (json.loads(text) if text.strip() else {}), response_headers
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors="replace")[:400]
                # 4xx other than 429 will not get better on a retry.
                if exc.code < 500 and exc.code != 429:
                    raise APIError(f"{method} {url} -> {exc.code}: {detail}") from exc
                last = APIError(f"{method} {url} -> {exc.code}: {detail}")
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last = APIError(f"{method} {url} -> {exc}")
            if attempt < attempts - 1:
                time.sleep(2 ** attempt)
        raise last if last else APIError(f"{method} {url} failed")

    def create_claim(self, claim_token: str | None = None) -> dict:
        """Create a directionless claim.

        The platform generates the claim_id but NOT the claim_token: that field
        is caller-supplied, and a claim created without one comes back with it
        empty and can only be redeemed by claim_id. The kiosk QR carries a
        claim_token, so one is always sent.
        """
        body: dict = {}
        if claim_token:
            body["claim_token"] = claim_token
        return self._send("POST", self._url("device_claims"), body)

    def set_claim_token(self, claim_id: str, claim_token: str) -> dict:
        """Backfill the token on a claim that was created without one."""
        return self._send("PATCH", self._url(f"device_claims/{claim_id}"),
                          {"set_claim_token": claim_token})

    def get_device(self, device_id: str) -> dict:
        return self._send("GET", self._url(f"devices/{device_id}"))

    def patch_device(self, device_id: str, body: dict) -> dict:
        return self._send("PATCH", self._url(f"devices/{device_id}"), body)

    def register_devices(self, body: dict) -> list[dict]:
        """POST /v2/org/{org}/devices. Returns the device list.

        This is the only call that returns device keys; the platform never
        hands them out again. Not retried (see _request).
        """
        url = f"{self.base_url}/v2/org/{self.org_id}/devices"
        response = self._send("POST", url, body, retry=False)
        devices = response.get("devices") if isinstance(response, dict) else response
        if not isinstance(devices, list):
            raise APIError(f"POST {url}: no devices array in response: "
                           f"{json.dumps(response)[:400]}")
        return devices

    def check_access(self) -> None:
        """Raise APIError if the token can't read this org's devices."""
        self._request("GET", self._url("devices?limit=10"))

    def list_devices(self, page_size: int = 1000):
        """Yield every device in the org, following Continuation-Token paging.

        Keys are not included; the platform only returns them at registration.
        """
        token = None
        while True:
            headers = {"Continuation-Token": token} if token else None
            body, response_headers = self._request(
                "GET", self._url(f"devices?limit={page_size}"), headers=headers)
            yield from body.get("devices") or []
            token = next((v for k, v in response_headers.items()
                          if k.lower() == "continuation-token"), None)
            if not token or not body.get("devices"):
                return


# --------------------------------------------------------------------------
# Claims
# --------------------------------------------------------------------------


def new_claim_token() -> str:
    """A caller-supplied claim token. The API accepts a UUID or a GS1-128."""
    return str(uuid.uuid4())


def activate_device(client, device_id: str) -> None:
    """PATCH set_activated:true on its own, as activate_devices.py does.

    One-way: an activated device is live (and billable) and the API cannot
    deactivate it. Idempotent, so re-activating is harmless.
    """
    try:
        client.patch_device(device_id, {"set_activated": True})
    except APIError as exc:
        raise ActivationError(f"claim linked but activation failed "
                       f"(the org may lack the entitlement): {exc}") from exc


def ensure_claim(client, device_id: str, row: dict, new: bool = False,
                 activate: bool = True) -> str:
    """Make sure `device_id` is linked to a claim that has a token, and (with
    activate=True) that the device is activated.

    Records claim_id / claim_token / error in `row` as it goes, so a failure
    part-way is resumable: a claim that was created but not linked is linked
    on the next call rather than duplicated. Returns what was done: "existing",
    "created", "linked" or "repaired". Raises APIError; the caller records it.

    new=True ignores any claim already recorded in the row and creates one.
    A failed activation leaves an error in the row, so the next call re-links
    (idempotent) and retries it. An "existing" claim is not re-activated here;
    callers that want that call activate_device() themselves.
    """
    claim_id = "" if new else (row.get("claim_id") or "").strip()
    token = "" if new else (row.get("claim_token") or "").strip()
    unlinked = bool((row.get("error") or "").strip())

    if claim_id and token and not unlinked:
        return "existing"

    action = "linked"
    if not claim_id:
        token = new_claim_token()
        claim = client.create_claim(claim_token=token)
        claim_id = claim.get("claim_id", "")
        if not claim_id:
            raise APIError(f"create claim returned no claim_id: {json.dumps(claim)[:200]}")
        row["claim_id"] = claim_id
        row["claim_token"] = claim.get("claim_token") or token
        action = "created"
    elif not token:
        token = new_claim_token()
        client.set_claim_token(claim_id, token)
        row["claim_token"] = token
        action = "repaired"
        if not unlinked:
            if activate:
                activate_device(client, device_id)
            row["error"] = ""
            return action

    client.patch_device(device_id, {"set_device_claim_id": claim_id})
    if activate:
        activate_device(client, device_id)
    row["error"] = ""
    return action


# --------------------------------------------------------------------------
# Claim links
# --------------------------------------------------------------------------


def claim_url(token: str, template: str = CLAIM_URL) -> str:
    """The dashboard link a claim QR code encodes."""
    return template.format(token=urllib.parse.quote(token.strip(), safe=""))


def file_stem(name: str) -> str:
    """A device name, made safe to use as a file name on Windows."""
    stem = UNSAFE_FILENAME.sub("_", name).strip().rstrip(".")
    return stem or "unnamed"
