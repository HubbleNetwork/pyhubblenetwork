# org delete-device Command Design

**Date:** 2026-03-25
**Feature:** Add `hubblenetwork org delete-device DEVICE_ID` CLI command to remove a registered device from an organisation.

---

## Background

The `org` subcommand currently supports: `info`, `list-devices`, `register-device`, `set-device-name`, `get-packets`. There is no way to delete a device from the CLI. The Hubble Cloud API exposes a single-device delete endpoint that is not yet wrapped in the SDK.

---

## API

**Endpoint:** `DELETE /api/org/{org_id}/devices/{device_id}`

**Auth:** Bearer token (`write-devices` scope required)

**Request body:** none

**Success response:** `200 OK` with JSON body:
```json
{"message": "Device deleted successfully"}
```

**Error response:** `400 Bad Request` with JSON body:
```json
{"code": 400, "description": "...", "name": "Bad Request"}
```

The endpoint path is identical to the existing `_update_device_endpoint` helper in `cloud.py`.

---

## Design

### CLI interface

```
hubblenetwork org delete-device DEVICE_ID [--yes/-y]
```

- `DEVICE_ID` — positional argument (UUID string), consistent with `set-device-name` and `get-packets`
- `--yes` / `-y` — boolean flag, skips the confirmation prompt (for scripting)
- Without `--yes`: prompts `"Delete device {device_id}? This cannot be undone. [y/N]"` using `click.confirm(..., abort=True)`; answering "no" prints `"Aborted!"` and exits non-zero
- Success output: `"Device {device_id} deleted."`

### Stack changes

Three files are modified; no new files are created in `src/`.

**`src/hubblenetwork/cloud.py`**

Add:
```python
def delete_device(
    credentials: Credentials,
    env: Environment,
    device_id: str,
) -> None:
    cloud_request(
        method="DELETE",
        path=_update_device_endpoint(credentials, device_id),
        credentials=credentials,
        env=env,
    )
```

`cloud_request` handles auth headers, error mapping via `raise_for_response`, and JSON parsing. It always returns a `(json_body, continuation_token)` tuple. `delete_device` calls `cloud_request` without capturing the return value — Python silently discards the tuple. This is safe because the API always returns `200 OK` with a JSON body; if the endpoint ever returns `204 No Content`, `cloud_request` will raise `BackendError("Non-JSON response")` due to the empty body, so this function assumes the documented `200 OK` response.

**`src/hubblenetwork/org.py`**

Add to `Organization`:
```python
def delete_device(self, device_id: str) -> None:
    cloud.delete_device(
        credentials=self.credentials,
        env=self.env,
        device_id=device_id,
    )
```

**`src/hubblenetwork/cli.py`**

Add after `register-device` (before `set-device-name`):
```python
@org.command("delete-device")
@click.argument("device-id", type=str)
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt.")
@pass_orgcfg
def delete_device(org: Organization, device_id: str, yes: bool) -> None:
    if not yes:
        click.confirm(
            f"Delete device {device_id}? This cannot be undone.",
            abort=True,
        )
    org.delete_device(device_id)
    click.echo(f"Device {device_id} deleted.")
```

---

## Error handling

| Scenario | Behaviour |
|---|---|
| API returns 400 (malformed request) | `raise_for_response` raises `RequestError` (a `BackendError` subclass) |
| Device not found (404) | `raise_for_response` falls through to generic `BackendError` (404 has no dedicated subclass in `map_http_status`) |
| Wrong credentials | `InvalidCredentialsError` raised during `Organization.__init__` (before command runs) |
| User answers "no" at prompt | `click.confirm(..., abort=True)` raises `click.Abort`; Click prints `"Aborted!"` and exits non-zero |

No new error types are needed.

---

## Testing

New file: `tests/test_org_delete_device.py`

### Unit tests for `Organization.delete_device`

Patch `hubblenetwork.org.cloud.delete_device`.

| Test | Setup | Expected |
|---|---|---|
| `test_delete_device_calls_cloud` | mock returns None | `cloud.delete_device` called with correct `device_id` |
| `test_delete_device_propagates_error` | mock raises `BackendError` | `BackendError` propagates |

### CLI integration tests

Use `CliRunner`. Patch `hubblenetwork.cli.Organization`.

| Test | Setup | Expected |
|---|---|---|
| `test_confirm_yes_deletes_device` | input `"y\n"`, mock org | exit code 0, `"deleted"` in output, `org.delete_device` called, prompt text `"This cannot be undone"` in output |
| `test_confirm_no_aborts` | input `"N\n"`, mock org | exit code != 0, `"Aborted"` in output, `org.delete_device` NOT called |
| `test_yes_flag_skips_prompt` | `--yes` flag, mock org | exit code 0, `"deleted"` in output, no prompt |
| `test_api_error_shows_message` | `org.delete_device` raises `BackendError("404: not found")` | exit code != 0, error surfaced |

---

## Files Changed

| File | Change |
|---|---|
| `src/hubblenetwork/cloud.py` | Add `delete_device` function |
| `src/hubblenetwork/org.py` | Add `Organization.delete_device` method |
| `src/hubblenetwork/cli.py` | Add `delete-device` command |
| `tests/test_org_delete_device.py` | New test file |
