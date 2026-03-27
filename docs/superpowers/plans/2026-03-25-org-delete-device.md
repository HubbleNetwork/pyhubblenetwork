# org delete-device Command Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `hubblenetwork org delete-device DEVICE_ID [--yes/-y]` CLI command that prompts for confirmation then calls `DELETE /api/org/{org_id}/devices/{device_id}`.

**Architecture:** Three-layer addition: `cloud.delete_device` wraps the HTTP call via the existing `cloud_request` helper; `Organization.delete_device` in `org.py` calls the cloud function; the CLI command uses `click.confirm` for the y/n prompt and `--yes`/`-y` to bypass it. All tests live in a new `tests/test_org_delete_device.py` file.

**Tech Stack:** Python, Click, httpx (via cloud_request), pytest, unittest.mock.

**Spec:** `docs/superpowers/specs/2026-03-25-org-delete-device-design.md`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `src/hubblenetwork/cloud.py` | Modify | Add `delete_device(credentials, env, device_id)` HTTP function |
| `src/hubblenetwork/org.py` | Modify | Add `Organization.delete_device(device_id)` method |
| `src/hubblenetwork/cli.py` | Modify | Add `@org.command("delete-device")` with confirmation prompt |
| `tests/test_org_delete_device.py` | Create | All tests for the three layers |

---

## Background: Key patterns in this codebase

**`cloud_request`** (in `cloud.py`, line ~78) is the shared HTTP helper. Call it with keyword-only args:
```python
cloud_request(method="DELETE", path="...", credentials=creds, env=env)
```
It always returns a `(json_body, continuation_token)` tuple. Callers can discard the return value — Python silently ignores it.

**`_update_device_endpoint(credentials, device_id)`** returns `f"/org/{credentials.org_id}/devices/{device_id}"`. The DELETE endpoint uses this same path.

**`pass_orgcfg`** (line 2532) is `click.make_pass_decorator(Organization, ensure=True)`. Every `org` subcommand uses it as a decorator to receive the `Organization` instance that the `org` group sets in `ctx.obj`.

**Existing `org` commands for reference:**
```python
@org.command("set-device-name")
@click.argument("device-id", type=str)
@click.argument("name", type=str)
@pass_orgcfg
def set_device_name(org: Organization, device_id: str, name: str) -> None:
    click.secho(str(org.set_device_name(device_id, name)))
```

**CLI test pattern:** Patch `hubblenetwork.cli.Organization` so the constructor call in the `org` group returns a mock. The mock instance becomes `ctx.obj`, and `pass_orgcfg` passes it as the `org` argument to the command.

```python
with patch("hubblenetwork.cli.Organization") as mock_org_cls:
    mock_org = mock_org_cls.return_value
    result = runner.invoke(cli, ["org", "--org-id", "fake-org", "--token", "fake-token", "delete-device", "some-id"])
```

---

## Task 1: `cloud.delete_device` function

**Files:**
- Modify: `src/hubblenetwork/cloud.py` (add after `update_device`, ~line 203)
- Create: `tests/test_org_delete_device.py`

- [ ] **Step 1: Create the test file with the cloud layer test**

Create `tests/test_org_delete_device.py`:

```python
"""Tests for org delete-device command."""
import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from hubblenetwork.org import Organization
from hubblenetwork.errors import BackendError
from hubblenetwork.cli import cli


class TestCloudDeleteDevice:
    def test_calls_cloud_request_with_delete_method(self):
        from hubblenetwork import cloud

        creds = MagicMock()
        creds.org_id = "org-123"
        env = MagicMock()

        with patch("hubblenetwork.cloud.cloud_request") as mock_req:
            cloud.delete_device(credentials=creds, env=env, device_id="dev-456")

        mock_req.assert_called_once_with(
            method="DELETE",
            path="/org/org-123/devices/dev-456",
            credentials=creds,
            env=env,
        )
```

- [ ] **Step 2: Run the test — confirm it fails**

```bash
source .venv/bin/activate && pytest tests/test_org_delete_device.py::TestCloudDeleteDevice -v
```

Expected: `AttributeError: module 'hubblenetwork.cloud' has no attribute 'delete_device'`

- [ ] **Step 3: Implement `cloud.delete_device` in `src/hubblenetwork/cloud.py`**

Add after `update_device` (around line 203), before `list_devices`:

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

- [ ] **Step 4: Run the test — confirm it passes**

```bash
source .venv/bin/activate && pytest tests/test_org_delete_device.py::TestCloudDeleteDevice -v
```

Expected: 1 test PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_org_delete_device.py src/hubblenetwork/cloud.py
git commit -s -m "feat(cloud): add delete_device function"
```

---

## Task 2: `Organization.delete_device` method

**Files:**
- Modify: `src/hubblenetwork/org.py` (add method to `Organization` class)
- Modify: `tests/test_org_delete_device.py` (add `TestOrgDeleteDevice` class)

- [ ] **Step 1: Add the org layer tests**

Append to `tests/test_org_delete_device.py`:

```python
class TestOrgDeleteDevice:
    def test_delete_device_calls_cloud(self):
        org = MagicMock(spec=Organization)
        org.credentials = MagicMock()
        org.env = MagicMock()

        with patch("hubblenetwork.org.cloud.delete_device") as mock_delete:
            Organization.delete_device(org, "dev-456")

        mock_delete.assert_called_once_with(
            credentials=org.credentials,
            env=org.env,
            device_id="dev-456",
        )

    def test_delete_device_propagates_error(self):
        org = MagicMock(spec=Organization)
        org.credentials = MagicMock()
        org.env = MagicMock()

        with patch(
            "hubblenetwork.org.cloud.delete_device",
            side_effect=BackendError("404: not found"),
        ):
            with pytest.raises(BackendError):
                Organization.delete_device(org, "dev-456")
```

- [ ] **Step 2: Run the tests — confirm they fail**

```bash
source .venv/bin/activate && pytest tests/test_org_delete_device.py::TestOrgDeleteDevice -v
```

Expected: `AttributeError: 'Organization' object has no attribute 'delete_device'`

- [ ] **Step 3: Implement `Organization.delete_device` in `src/hubblenetwork/org.py`**

Add after `set_device_name` (around line 99), before `list_devices`:

```python
def delete_device(self, device_id: str) -> None:
    cloud.delete_device(
        credentials=self.credentials,
        env=self.env,
        device_id=device_id,
    )
```

- [ ] **Step 4: Run the tests — confirm they pass**

```bash
source .venv/bin/activate && pytest tests/test_org_delete_device.py::TestOrgDeleteDevice -v
```

Expected: 2 tests PASS

- [ ] **Step 5: Run all tests so far**

```bash
source .venv/bin/activate && pytest tests/test_org_delete_device.py -v
```

Expected: 3 tests PASS

- [ ] **Step 6: Commit**

```bash
git add tests/test_org_delete_device.py src/hubblenetwork/org.py
git commit -s -m "feat(org): add Organization.delete_device method"
```

---

## Task 3: `delete-device` CLI command

**Files:**
- Modify: `src/hubblenetwork/cli.py` (add command after `register-device`, ~line 2618)
- Modify: `tests/test_org_delete_device.py` (add `TestDeleteDeviceCLI` class)

### Background: How `click.confirm` works

`click.confirm("message", abort=True)`:
- Prints `"message [y/N]: "` and reads input
- If user types `y`/`Y`/`yes`: returns `True`, execution continues
- If user types anything else (including `N`/`n`/empty): raises `click.exceptions.Abort`
- `click.exceptions.Abort` causes Click to print `"Aborted!"` and exit with code 1

In `CliRunner`, pass `input="y\n"` or `input="N\n"` to simulate user input.

- [ ] **Step 1: Add the CLI integration tests**

Append to `tests/test_org_delete_device.py`:

```python
class TestDeleteDeviceCLI:
    def test_confirm_yes_deletes_device(self):
        runner = CliRunner()
        device_id = "abc-123"

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org = mock_org_cls.return_value
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "delete-device", device_id],
                input="y\n",
            )

        assert result.exit_code == 0
        assert "deleted" in result.output
        assert "This cannot be undone" in result.output
        mock_org.delete_device.assert_called_once_with(device_id)

    def test_confirm_no_aborts(self):
        runner = CliRunner()
        device_id = "abc-123"

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org = mock_org_cls.return_value
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "delete-device", device_id],
                input="N\n",
            )

        assert result.exit_code != 0
        assert "Aborted" in result.output
        mock_org.delete_device.assert_not_called()

    def test_yes_flag_skips_prompt(self):
        runner = CliRunner()
        device_id = "abc-123"

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org = mock_org_cls.return_value
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "delete-device", device_id, "--yes"],
            )

        assert result.exit_code == 0
        assert "deleted" in result.output
        assert "This cannot be undone" not in result.output
        mock_org.delete_device.assert_called_once_with(device_id)

    def test_api_error_surfaces(self):
        runner = CliRunner()
        device_id = "abc-123"

        with patch("hubblenetwork.cli.Organization") as mock_org_cls:
            mock_org = mock_org_cls.return_value
            mock_org.delete_device.side_effect = BackendError("404: not found")
            result = runner.invoke(
                cli,
                ["org", "--org-id", "fake-org", "--token", "fake-token",
                 "delete-device", device_id, "--yes"],
            )

        assert result.exit_code != 0
```

- [ ] **Step 2: Run the tests — confirm they fail**

```bash
source .venv/bin/activate && pytest tests/test_org_delete_device.py::TestDeleteDeviceCLI -v
```

Expected: `UsageError: No such command 'delete-device'` — the command doesn't exist yet

- [ ] **Step 3: Implement the `delete-device` command in `src/hubblenetwork/cli.py`**

Find `@org.command("set-device-name")` (around line 2620). Insert the following **before** it:

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

- [ ] **Step 4: Run the CLI tests — confirm they pass**

```bash
source .venv/bin/activate && pytest tests/test_org_delete_device.py::TestDeleteDeviceCLI -v
```

Expected: 4 tests PASS

- [ ] **Step 5: Run the full test file**

```bash
source .venv/bin/activate && pytest tests/test_org_delete_device.py -v
```

Expected: 7 tests PASS

- [ ] **Step 6: Run the full test suite — confirm no regressions**

```bash
source .venv/bin/activate && pytest -v
```

Expected: all tests PASS

- [ ] **Step 7: Run the linter**

```bash
source .venv/bin/activate && ruff check src/hubblenetwork/cli.py src/hubblenetwork/cloud.py src/hubblenetwork/org.py
```

Expected: no errors

- [ ] **Step 8: Commit**

```bash
git add tests/test_org_delete_device.py src/hubblenetwork/cli.py
git commit -s -m "feat(cli): add org delete-device command with confirmation prompt"
```
