# Product Requirements Document: Hubble Ready CLI Testing Framework

**Version:** 1.0
**Created:** 2026-02-02
**Purpose:** Enable automated firmware testing for Hubble Ready devices through enhanced CLI commands
**Target:** AI agents (Claude Code) and firmware developers

---

## 1. Introduction

### 1.1 Problem Statement

The current `hubblenetwork ready` CLI commands block automated firmware testing workflows due to three critical limitations:

1. **Interactive Prompts Block Automation** - Commands require manual device selection, preventing use in test scripts and CI/CD pipelines
2. **Coarse-Grained Operations** - Only full provisioning flow available; no way to test individual GATT characteristics in isolation
3. **No Automated Validation** - No comprehensive test suites to validate firmware spec compliance

These limitations prevent AI-driven development loops where Claude Code generates firmware implementations, flashes them to hardware, and validates compliance programmatically.

### 1.2 Solution

Extend the `hubblenetwork ready` CLI command group with:

1. **Non-Interactive Mode** - Add `--address` parameter to bypass device selection prompts
2. **Granular Commands** - Individual read/write commands for each GATT characteristic
3. **Validation Framework** - Automated test suites (`validate`, `test`, `test-errors`) with machine-readable JSON output
4. **Consistent Interface** - Unified JSON output structure, timeout controls, and exit codes across all commands

### 1.3 Target Users

1. **AI Agents (Claude Code)** - Automated firmware testing workflows
2. **Firmware Developers** - Isolated characteristic testing during development
3. **QA Engineers** - Regression testing and spec compliance validation

### 1.4 Current State Analysis

This section documents the baseline CLI implementation as of 2026-02-02 and identifies gaps against the Hubble Ready Specification v0.0.1.

#### 1.4.1 Existing Commands

The `hubblenetwork ready` command group currently provides 6 commands:

| Command | Line | Capability | Limitations |
|---------|------|------------|-------------|
| `ready scan` | cli.py:852 | Discover devices advertising 0xFCA7 | ❌ Requires interactive selection<br>❌ No address filtering |
| `ready info` | cli.py:1012 | Read all characteristics | ❌ Requires interactive selection<br>❌ Reads all or nothing |
| `ready read-status` | cli.py:1202 | Read Status characteristic (0x0001) | ✅ Non-interactive via --address<br>❌ Only one characteristic |
| `ready read-key-info` | cli.py:1301 | Read Device Key characteristic (0x0003) | ✅ Non-interactive via --address<br>❌ Only one characteristic |
| `ready read-config` | cli.py:1385 | Read Device Configuration (0x0004) | ✅ Non-interactive via --address<br>❌ Only one characteristic |
| `ready provision` | cli.py:1470 | Full provisioning flow | ❌ Interactive device selection<br>❌ Open Mode only<br>❌ Atomic operation (can't test individual steps) |

#### 1.4.2 Specification Coverage Analysis

##### ✅ Well-Covered Areas

**Advertising (Spec Section 3):**
- `ready scan` successfully discovers 0xFCA7 devices
- Returns device name, address, RSSI
- Supports both tabular and JSON output

**GATT Read Operations (Spec Section 4):**
- Status characteristic (0x0001): `read-status` command parses version, mode, and all flags
- Device Key characteristic (0x0003): `read-key-info` command identifies encryption mode and key size
- Device Configuration (0x0004): `read-config` command parses EID type, rotation period, pool size
- General inspection: `info` command reads all characteristics with parsed values

**Provisioning - Open Mode (Spec Section 6):**
- `ready provision` implements full Open Mode flow:
  - Connects and verifies Open Mode via Status characteristic
  - Auto-detects encryption mode from device
  - Registers device with Hubble backend
  - Writes Device Key, Configuration, and Epoch Time
  - Verifies all flags set correctly

##### ❌ Critical Testing Gaps

The following capabilities are required by the specification but not testable with current CLI:

**1. Epoch Time Characteristic (Spec Section 4.2.5)**
- **Missing:** No standalone `read-time` command for characteristic 0x0005
- **Impact:** Cannot verify epoch time reads independently
- **Spec Requirement:** Read returns 8-byte UTC timestamp (little-endian)
- **User Story:** US-006 (to be implemented)

**2. Individual Write Operations (Spec Section 4.2)**
- **Missing:** No write commands for any characteristics
- **Impact:** Cannot test:
  - Write error conditions (ATT codes 0x80-0x87)
  - Partial provisioning states
  - Recovery from write failures
  - Out-of-order write sequences
  - Invalid payload validation
- **Spec Requirements:**
  - Device Key: 16 or 32 bytes matching encryption mode
  - Device Configuration: 12 bytes with validation
  - Epoch Time: 8 bytes UTC timestamp
- **User Stories:** US-010, US-011, US-012 (to be implemented)

**3. Challenge/Response & Authentication (Spec Section 5)**
- **Missing:** No support for Manufacturer-Locked Mode testing
- **Impact:** Cannot test:
  - Challenge generation and reading (64 bytes: pubkey + nonce)
  - Signature writing and verification
  - Authentication state transitions (`Locked` flag clearing)
  - DIS characteristic integration (Mfg Name, Serial Number)
- **Spec Requirements:**
  - Challenge/Response characteristic (0x0002)
  - Ed25519 signature verification
  - Device Information Service reads
- **Note:** Explicitly marked as Non-Goal (Section 3, item 1)

**4. Device Information Service (Spec Sections 5.4, 6.5)**
- **Missing:** No command to read DIS characteristics
- **Impact:** Cannot verify:
  - Manufacturer Name String (0x2A29) - Required for locked devices
  - Serial Number String (0x2A25) - Required for locked devices
  - Model Number String (0x2A24) - Optional
  - Firmware Revision String (0x2A26) - Optional
- **User Story:** US-009 (to be implemented)

**5. Error Handling & Validation (Spec Section 8)**
- **Missing:** No way to trigger or observe error conditions
- **Impact:** Cannot verify firmware correctly returns:
  - ATT error codes: 0x03, 0x05, 0x06, 0x0D, 0x0F
  - Application errors: 0x80 (Auth Required), 0x81 (Auth Failed)
  - Validation errors: 0x84-0x87 (Invalid EID Type, Rotation Period, Pool Size, Reserved Field)
- **Spec Requirements:**
  - Invalid Attribute Value Length (0x0D) for wrong write sizes
  - Insufficient Encryption (0x0F) for unencrypted access
  - Invalid EID Type (0x84) for unknown EID type values
  - Invalid Pool Size (0x86) for out-of-range pool sizes
- **User Story:** US-016 (to be implemented, marked Future)

**6. Status Indications (Spec Section 4.2.1)**
- **Missing:** No command to subscribe to Status characteristic indications
- **Impact:** Cannot verify:
  - Asynchronous status updates after writes
  - CCCD (Client Characteristic Configuration Descriptor) functionality
  - Flag transitions during provisioning
- **Note:** Marked as Non-Goal (Section 3, item 3: "Real-time status monitoring")

**7. Protocol Compliance Validation (Spec Sections 4, 6, 7)**
- **Missing:** No automated test suites
- **Impact:** Cannot validate:
  - Protocol version compatibility (semantic versioning)
  - MTU negotiation (minimum 128 bytes required per spec)
  - Pairing and encryption establishment
  - State machine transitions (Unprovisioned ↔ Provisioned)
  - Flag transition correctness
  - Write order independence
- **User Stories:** US-014, US-015 (to be implemented, marked Future)

#### 1.4.3 Gap Summary

| Category | Spec Required | Currently Testable | Gap |
|----------|--------------|-------------------|-----|
| **Characteristic Reads** | 5 characteristics | 4 of 5 (missing Epoch Time) | US-006 |
| **Characteristic Writes** | 3 writable chars | 0 (only via full provision flow) | US-010, US-011, US-012 |
| **Authentication** | Challenge/Response + DIS | 0 (Open Mode only) | Non-Goal |
| **DIS Reads** | 4 characteristics | 0 | US-009 |
| **Error Validation** | 11 error codes | 0 | US-016 (Future) |
| **Automated Testing** | Spec compliance validation | 0 | US-014, US-015 (Future) |

The current implementation is **production-ready for Open Mode provisioning** but **insufficient for comprehensive firmware testing and spec compliance validation**. The user stories in Section 4 address the testability gaps while maintaining backward compatibility.

---

## 2. Goals

### 2.1 Primary Goals

- ✅ Enable fully automated firmware testing workflows without human interaction
- ✅ Support granular GATT characteristic testing for isolated development
- ✅ Provide comprehensive spec compliance validation with detailed test results
- ✅ Maintain 100% backward compatibility with existing CLI behavior

### 2.2 Success Metrics

- All 17 user stories implemented and passing tests
- Zero breaking changes to existing commands
- All commands return correct exit codes (0=success, 1=validation fail, 2=error)
- JSON output is valid, parseable, and follows specification
- Test coverage >80% for new functions in ready.py

---

## 3. Non-Goals

The following are explicitly **OUT OF SCOPE** for this implementation:

1. ❌ Manufacturer-Locked Mode support (Ed25519 authentication testing)
2. ❌ Batch testing multiple devices in a single command
3. ❌ Real-time status monitoring (watch mode)
4. ❌ Mock/stub hardware support for testing without physical devices
5. ❌ HTML/PDF report generation
6. ❌ CI/CD integration templates (GitHub Actions, GitLab CI)

---

## 4. User Stories

Stories are ordered by dependency for sequential implementation. Each story is self-contained with complete implementation details for AI execution.

---

### US-001: Add --address parameter to ready scan

**Persona**: AI agent running automated firmware tests

**Description**: As an AI agent, I want to filter scan results to a specific device address so that I can verify a specific device is advertising without interactive selection.

**Business Value**: Enables automation by allowing scripts to verify device presence programmatically.

**Dependencies**: None (foundation story)

**Implementation Details**:

*CLI Changes (cli.py, ready scan command at line 769):*

Add parameter to existing command:
```python
@ready.command("scan")
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=10.0,
    show_default=True,
    help="Scan timeout in seconds",
)
@click.option(
    "--address",
    type=str,
    required=False,
    help="Filter to specific BLE MAC address (optional)",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_scan(timeout: float = 10.0, address: Optional[str] = None, output_format: str = "tabular") -> None:
```

*Behavior*:
- If `--address` omitted: existing behavior (show all devices)
- If `--address` provided: filter `devices_found` list to exact MAC address match (case-insensitive)
- If no match found: return empty array (exit code 0, not an error)
- Filter logic: `if address and dev.address.lower() != address.lower(): skip device`

*JSON Output (when filtered):*
```json
[
  {"name": "Device-12345", "address": "AA:BB:CC:DD:EE:FF", "rssi": -45}
]
```

*JSON Output (no match):*
```json
[]
```

**Acceptance Criteria**:
- [ ] Command executes: `hubblenetwork ready scan --address AA:BB:CC:DD:EE:FF --format json`
- [ ] Returns empty array if device not found (exit code 0)
- [ ] Returns single-element array if device found
- [ ] Case-insensitive address matching works (test AA:BB:CC vs aa:bb:cc)
- [ ] Existing behavior unchanged when `--address` omitted
- [ ] Tabular output shows only filtered device when `--address` provided
- [ ] Typecheck passes: `mypy src/hubblenetwork/cli.py`
- [ ] Lint passes: `ruff check src/hubblenetwork/cli.py`

**Testing**:
```bash
# Manual test with real device
hubblenetwork ready scan --address AA:BB:CC:DD:EE:FF --format json

# Test case-insensitivity
hubblenetwork ready scan --address aa:bb:cc:dd:ee:ff --format json

# Test no match (should return empty array)
hubblenetwork ready scan --address 00:00:00:00:00:00 --format json

# Unit test (create new test file tests/test_cli_ready.py)
pytest tests/test_cli_ready.py::test_ready_scan_with_address -v
```

---

### US-002: Add --address parameter to ready info

**Persona**: Firmware developer testing characteristic implementation

**Description**: As a firmware developer, I want to connect directly to a device by address so that I can quickly inspect characteristics without interactive selection during development.

**Business Value**: Speeds up development iteration by eliminating manual device selection steps.

**Dependencies**: None (foundation story)

**Implementation Details**:

*CLI Changes (cli.py, ready info command at line 885):*

Add parameter and modify device selection logic:
```python
@ready.command("info")
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=10.0,
    show_default=True,
    help="Scan timeout in seconds",
)
@click.option(
    "--address",
    type=str,
    required=False,
    help="Connect directly to specific BLE MAC address (bypass scan/selection)",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_info(timeout: float = 10.0, address: Optional[str] = None, output_format: str = "tabular") -> None:
```

*Behavior*:
- If `--address` provided: skip scan and interactive selection, connect directly to address
- If `--address` omitted: existing behavior (scan + interactive selection)
- On connection failure: JSON output with error, exit code 2

*Connection Logic*:
```python
if address:
    # Direct connection mode
    if not use_json:
        click.echo(f"Connecting to {address}...")
    selected_address = address
    selected_name = None  # Will be populated from characteristics if available
else:
    # Existing scan + selection logic
    if not use_json:
        click.secho("Scanning for Hubble Ready devices...")
    devices = ready_mod.scan_ready_devices(timeout=timeout)
    # ... rest of existing logic
```

*JSON Output (success):*
```json
{
  "device": {
    "address": "AA:BB:CC:DD:EE:FF",
    "name": null
  },
  "characteristics": [
    {
      "name": "Status",
      "uuid": "00000001-fca7-4000-8000-00805f9b34fb",
      "raw_hex": "000001000000",
      "value": "v0.0.1, Open Mode\nKey=No, Config=No, Time=No"
    }
  ]
}
```

*JSON Output (connection error):*
```json
{
  "error": "Connection failed: Device with address AA:BB:CC:DD:EE:FF was not found"
}
```

**Acceptance Criteria**:
- [ ] Command executes: `hubblenetwork ready info --address AA:BB:CC:DD:EE:FF --format json`
- [ ] Connects directly without scanning when `--address` provided
- [ ] Returns error with exit code 2 if connection fails
- [ ] Existing scan+selection behavior unchanged when `--address` omitted
- [ ] JSON output includes all characteristics on success
- [ ] Tabular output works with `--address` parameter
- [ ] Typecheck passes: `mypy src/hubblenetwork/cli.py`
- [ ] Lint passes: `ruff check src/hubblenetwork/cli.py`

**Testing**:
```bash
# Manual test
hubblenetwork ready info --address AA:BB:CC:DD:EE:FF --format json

# Test connection error (invalid address)
hubblenetwork ready info --address 00:00:00:00:00:00 --format json

# Verify exit code on error
hubblenetwork ready info --address 00:00:00:00:00:00 --format json; echo "Exit code: $?"

# Unit test
pytest tests/test_cli_ready.py::test_ready_info_with_address -v
```

---

### US-003: Add --timeout parameter to all ready commands

**Persona**: QA engineer running automated test suites

**Description**: As a QA engineer, I want to control connection timeouts for all ready commands so that I can optimize test suite execution time and handle flaky connections.

**Business Value**: Prevents tests from hanging indefinitely on connection failures.

**Dependencies**: None (foundation story)

**Implementation Details**:

*CLI Changes (cli.py):*

All ready commands already have `--timeout` parameter for scan timeout. No changes needed for:
- `ready scan` (line 769) - already has `--timeout`
- `ready info` (line 885) - already has `--timeout`
- `ready provision` (line 984) - already has `--timeout`

This story documents the existing behavior and ensures consistency for new commands to be added in later stories.

*Default Timeout Values*:
- `ready scan`: 10.0 seconds (already implemented)
- `ready info`: 10.0 seconds (already implemented)
- `ready provision`: 10.0 seconds for scan, 30.0 for connection (already implemented)
- New commands (to be added): 30.0 seconds default

*Behavior*:
- Timeout applies to BLE connection establishment and GATT operations
- If timeout exceeded: return error with exit code 2
- Timeout is a float value in seconds

**Acceptance Criteria**:
- [ ] All existing ready commands support `--timeout` parameter
- [ ] Documentation confirms default timeout values
- [ ] New commands added in future stories must support `--timeout`
- [ ] Timeout errors return exit code 2 consistently
- [ ] JSON error output includes timeout information

**Testing**:
```bash
# Verify existing commands accept timeout
hubblenetwork ready scan --timeout 5 --format json
hubblenetwork ready info --timeout 5 --format json
hubblenetwork ready provision --timeout 5  # (requires credentials)

# Verify timeout is enforced (use invalid address to trigger timeout)
time hubblenetwork ready info --address 00:00:00:00:00:00 --timeout 2 --format json
# Should complete in ~2 seconds, not hang indefinitely
```

---

### US-004: Add ATT error codes and BleError exception to errors.py

**Persona**: AI agent implementing firmware error handling

**Description**: As an AI agent, I want ATT error code constants and mappings defined in errors.py so that I can properly handle and report GATT operation failures in validation tests.

**Business Value**: Enables consistent error handling and reporting across all BLE operations.

**Dependencies**: None (foundation story)

**Implementation Details**:

*File: src/hubblenetwork/errors.py*

Add after line 59 (after `DecryptionError`):

```python
class BleError(HubbleError):
    """BLE GATT operation failed (connection, read, write, etc.)."""

    def __init__(self, message: str, att_error_code: Optional[int] = None):
        """
        Args:
            message: Human-readable error message
            att_error_code: ATT error code from BleakError if available
        """
        super().__init__(message)
        self.att_error_code = att_error_code

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dictionary."""
        return {
            "code": f"0x{self.att_error_code:02X}" if self.att_error_code else None,
            "name": ATT_ERROR_NAMES.get(self.att_error_code, "Unknown Error") if self.att_error_code else None,
            "message": str(self)
        }


# ATT Error Code Constants
ATT_ERROR_INVALID_LENGTH = 0x0D
ATT_ERROR_INSUFFICIENT_ENCRYPTION = 0x0F
ATT_ERROR_INVALID_EID_TYPE = 0x84
ATT_ERROR_INVALID_ROTATION_PERIOD = 0x85
ATT_ERROR_INVALID_POOL_SIZE = 0x86
ATT_ERROR_INVALID_RESERVED_FIELD = 0x87

# ATT Error Code to Human-Readable Name Mapping
ATT_ERROR_NAMES = {
    0x0D: "Invalid Attribute Value Length",
    0x0F: "Insufficient Encryption",
    0x84: "Invalid EID Type",
    0x85: "Invalid Rotation Period",
    0x86: "Invalid Pool Size",
    0x87: "Invalid Reserved Field",
}


def extract_att_error_code(exception: Exception) -> Optional[int]:
    """
    Extract ATT error code from BleakError exception.

    BleakError messages contain ATT error codes in format:
    "Characteristic ... returned error: 0x0D"

    Args:
        exception: Exception from Bleak GATT operation

    Returns:
        ATT error code as integer, or None if not found
    """
    import re
    error_msg = str(exception)
    match = re.search(r'error:\s*0x([0-9A-Fa-f]{2})', error_msg)
    if match:
        return int(match.group(1), 16)
    return None
```

*Update __all__ export list (line 74):*
```python
__all__ = [
    "HubbleError",
    "BackendError",
    "RequestError",
    "InternalServerError",
    "NetworkError",
    "APITimeout",
    "InvalidCredentialsError",
    "ValidationError",
    "ScanError",
    "DecryptionError",
    "BleError",  # NEW
    "InvalidDeviceError",
    "ElfFetchError",
    "FlashError",
    "raise_for_response",
    "map_http_status",
    "ATT_ERROR_INVALID_LENGTH",  # NEW
    "ATT_ERROR_INSUFFICIENT_ENCRYPTION",  # NEW
    "ATT_ERROR_INVALID_EID_TYPE",  # NEW
    "ATT_ERROR_INVALID_ROTATION_PERIOD",  # NEW
    "ATT_ERROR_INVALID_POOL_SIZE",  # NEW
    "ATT_ERROR_INVALID_RESERVED_FIELD",  # NEW
    "ATT_ERROR_NAMES",  # NEW
    "extract_att_error_code",  # NEW
]
```

**Acceptance Criteria**:
- [ ] `BleError` exception class defined with `att_error_code` attribute
- [ ] All 6 ATT error code constants defined
- [ ] `ATT_ERROR_NAMES` dictionary maps all codes to human-readable names
- [ ] `extract_att_error_code()` function parses BleakError messages
- [ ] All new exports added to `__all__`
- [ ] `BleError.to_dict()` method returns JSON-serializable format
- [ ] Typecheck passes: `mypy src/hubblenetwork/errors.py`
- [ ] Lint passes: `ruff check src/hubblenetwork/errors.py`

**Testing**:
```bash
# Unit tests (create tests/test_errors.py if not exists)
pytest tests/test_errors.py::test_att_error_codes -v
pytest tests/test_errors.py::test_ble_error_to_dict -v
pytest tests/test_errors.py::test_extract_att_error_code -v

# Manual verification
python3 -c "from hubblenetwork.errors import ATT_ERROR_NAMES; print(ATT_ERROR_NAMES)"
python3 -c "from hubblenetwork.errors import BleError; e = BleError('test', 0x0D); print(e.to_dict())"
```

---

### US-005: Update JSON output structure to specification format

**Persona**: AI agent parsing test results

**Description**: As an AI agent, I want all ready commands to output JSON in a consistent, documented structure so that I can reliably parse test results and make decisions.

**Business Value**: Enables reliable programmatic parsing of command results.

**Dependencies**: US-004 (requires BleError for error formatting)

**Implementation Details**:

*Standard JSON Output Structure*:

All commands must follow this structure:

```json
{
  "success": true,
  "command": "ready <subcommand>",
  "device": {
    "address": "AA:BB:CC:DD:EE:FF",
    "name": "Device-12345"
  },
  "result": {
    // Command-specific result data
  },
  "error": null,
  "duration_ms": 1234
}
```

Error structure:
```json
{
  "success": false,
  "command": "ready <subcommand>",
  "device": {
    "address": "AA:BB:CC:DD:EE:FF"
  },
  "error": {
    "code": "0x0D",
    "name": "Invalid Attribute Value Length",
    "message": "Detailed error message"
  },
  "duration_ms": 1234
}
```

*Implementation Approach*:

Create helper functions in cli.py:

```python
def _format_ready_json_success(
    command: str,
    device_address: str,
    result: dict,
    duration_ms: int,
    device_name: Optional[str] = None
) -> str:
    """Format successful command result as JSON."""
    return json.dumps({
        "success": True,
        "command": command,
        "device": {
            "address": device_address,
            "name": device_name
        },
        "result": result,
        "error": None,
        "duration_ms": duration_ms
    }, indent=2)


def _format_ready_json_error(
    command: str,
    device_address: Optional[str],
    error: Exception,
    duration_ms: int
) -> str:
    """Format error result as JSON."""
    error_dict = {
        "code": None,
        "name": "Error",
        "message": str(error)
    }

    # If BleError, extract ATT error code info
    if isinstance(error, BleError):
        error_dict = error.to_dict()

    return json.dumps({
        "success": False,
        "command": command,
        "device": {
            "address": device_address
        } if device_address else None,
        "error": error_dict,
        "duration_ms": duration_ms
    }, indent=2)
```

*Existing Command Updates*:

Update `ready scan` to use new format (minimal changes since it returns array):
- Array format is acceptable for scan (special case)
- Individual device objects follow simplified format

Update `ready info` to use new format:
- Wrap characteristics array in standard structure
- Add duration_ms tracking

**Acceptance Criteria**:
- [ ] Helper functions `_format_ready_json_success` and `_format_ready_json_error` implemented
- [ ] All top-level fields present: success, command, device, result/error, duration_ms
- [ ] Error objects include code, name, message fields
- [ ] BleError exceptions format correctly with ATT error codes
- [ ] Device object includes address (required) and name (optional)
- [ ] Duration tracking implemented (use time.monotonic() for timing)
- [ ] JSON is valid and parseable (test with `jq` or `json.loads()`)
- [ ] Typecheck passes: `mypy src/hubblenetwork/cli.py`
- [ ] Lint passes: `ruff check src/hubblenetwork/cli.py`

**Testing**:
```bash
# Test updated ready info command
hubblenetwork ready info --address AA:BB:CC:DD:EE:FF --format json | jq .

# Verify structure
hubblenetwork ready info --address AA:BB:CC:DD:EE:FF --format json | jq '.success, .command, .device, .duration_ms'

# Test error format
hubblenetwork ready info --address 00:00:00:00:00:00 --format json | jq '.error'

# Unit tests
pytest tests/test_cli_ready.py::test_json_output_structure -v
```

---

### US-006: Add WriteResult, TestResult, ValidationResult dataclasses to ready.py

**Persona**: Firmware developer implementing test infrastructure

**Description**: As a firmware developer, I want typed dataclasses for write results and test results so that the codebase maintains type safety and clear interfaces for testing functions.

**Business Value**: Improves code maintainability and enables IDE autocomplete for developers.

**Dependencies**: None (foundation story)

**Implementation Details**:

*File: src/hubblenetwork/ready.py*

Add after line 286 (after DeviceKeyInfo dataclass):

```python
@dataclass
class WriteResult:
    """Result of a write operation to a GATT characteristic."""

    success: bool
    characteristic_name: str  # Human-readable name
    error_code: Optional[int] = None  # ATT error code if failed
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dictionary."""
        result = {
            "success": self.success,
            "characteristic": self.characteristic_name,
        }
        if not self.success:
            result["error"] = {
                "code": f"0x{self.error_code:02X}" if self.error_code else None,
                "message": self.error_message
            }
        if self.duration_ms is not None:
            result["duration_ms"] = self.duration_ms
        return result


@dataclass
class TestResult:
    """Result of a single test in a validation suite."""

    name: str  # Test identifier (e.g., "connection", "status_format")
    status: str  # "pass", "fail", "skip"
    duration_ms: int
    details: Optional[dict] = None  # Test-specific details
    error: Optional[str] = None  # Error message if failed

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dictionary."""
        result = {
            "name": self.name,
            "status": self.status,
            "duration_ms": self.duration_ms
        }
        if self.details:
            result["details"] = self.details
        if self.error:
            result["error"] = self.error
        return result


@dataclass
class ValidationResult:
    """Result of a validation test suite (validate or test command)."""

    device_address: str
    device_name: Optional[str]
    tests: List[TestResult]

    @property
    def summary(self) -> dict:
        """Generate summary statistics."""
        total = len(self.tests)
        passed = sum(1 for t in self.tests if t.status == "pass")
        failed = sum(1 for t in self.tests if t.status == "fail")
        skipped = sum(1 for t in self.tests if t.status == "skip")
        duration_ms = sum(t.duration_ms for t in self.tests)

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "duration_ms": duration_ms
        }

    @property
    def success(self) -> bool:
        """Return True if all tests passed."""
        return all(t.status == "pass" for t in self.tests)

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dictionary."""
        return {
            "device": {
                "address": self.device_address,
                "name": self.device_name
            },
            "tests": [t.to_dict() for t in self.tests],
            "summary": self.summary
        }
```

*Update imports at top of file (after line 13):*
```python
from typing import TYPE_CHECKING, Callable, List, Optional, Dict
```

**Acceptance Criteria**:
- [ ] `WriteResult` dataclass defined with all fields
- [ ] `TestResult` dataclass defined with all fields
- [ ] `ValidationResult` dataclass defined with all fields
- [ ] All dataclasses have `to_dict()` methods for JSON serialization
- [ ] `ValidationResult.summary` property calculates test statistics
- [ ] `ValidationResult.success` property returns boolean
- [ ] Typecheck passes: `mypy src/hubblenetwork/ready.py`
- [ ] Lint passes: `ruff check src/hubblenetwork/ready.py`
- [ ] Dataclasses are importable: `from hubblenetwork.ready import WriteResult, TestResult, ValidationResult`

**Testing**:
```bash
# Manual verification
python3 -c "from hubblenetwork.ready import WriteResult, TestResult, ValidationResult; print('Import successful')"

# Unit tests
pytest tests/test_ready_dataclasses.py::test_write_result -v
pytest tests/test_ready_dataclasses.py::test_test_result -v
pytest tests/test_ready_dataclasses.py::test_validation_result -v

# Typecheck
mypy src/hubblenetwork/ready.py
```

---

### US-007: Implement ready read-status command

**Persona**: Firmware developer testing Status characteristic

**Description**: As a firmware developer, I want to read just the Status characteristic so that I can verify version and provisioning flags during development without running full provisioning.

**Business Value**: Enables rapid iteration on Status characteristic implementation.

**Dependencies**: US-001 (--address), US-003 (--timeout), US-004 (BleError), US-005 (JSON format), US-006 (dataclasses)

**Implementation Details**:

*File: src/hubblenetwork/ready.py*

Add after line 421 (after `connect_and_read_characteristics` function):

```python
async def _read_status_async(address: str, timeout: float = 30.0) -> StatusCharacteristic:
    """
    Async implementation: Connect and read Status characteristic only.

    Args:
        address: BLE MAC address
        timeout: Connection timeout in seconds

    Returns:
        StatusCharacteristic with parsed data

    Raises:
        BleError: If connection or read fails
    """
    from .errors import BleError, extract_att_error_code
    from bleak.exc import BleakError as BleakException

    try:
        async with BleakClient(address, timeout=timeout) as client:
            data = await client.read_gatt_char(CHAR_STATUS_UUID)
            return StatusCharacteristic.from_bytes(bytes(data))
    except BleakException as e:
        att_code = extract_att_error_code(e)
        raise BleError(f"Failed to read Status characteristic: {e}", att_error_code=att_code)
    except Exception as e:
        raise BleError(f"Failed to read Status characteristic: {e}")


def read_status(address: str, timeout: float = 30.0) -> StatusCharacteristic:
    """
    Connect to device and read Status characteristic only.

    Args:
        address: BLE MAC address
        timeout: Connection timeout in seconds

    Returns:
        StatusCharacteristic with parsed data

    Raises:
        BleError: If connection or read fails
    """
    try:
        return asyncio.run(_read_status_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_read_status_async(address, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
```

*File: src/hubblenetwork/cli.py*

Add after `ready_provision` command (around line 1115):

```python
@ready.command("read-status")
@click.option(
    "--address",
    type=str,
    required=True,
    help="BLE MAC address of device",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_read_status(address: str, timeout: float = 30.0, output_format: str = "tabular") -> None:
    """
    Read Status characteristic from a Hubble Ready device.

    Connects to the device and reads only the Status characteristic,
    returning version, mode (Open/Locked), and provisioning flags.

    Example:
      hubblenetwork ready read-status --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready read-status --address AA:BB:CC:DD:EE:FF --format json
    """
    import time
    from hubblenetwork.errors import BleError

    use_json = output_format.lower() == "json"
    start = time.monotonic()

    try:
        status = ready_mod.read_status(address=address, timeout=timeout)
        duration_ms = int((time.monotonic() - start) * 1000)

        if use_json:
            result = {
                "version": {
                    "major": status.version_major,
                    "minor": status.version_minor,
                    "patch": status.version_patch
                },
                "flags": {
                    "locked": status.is_locked,
                    "key_written": status.key_written,
                    "config_written": status.config_written,
                    "epoch_time_written": status.epoch_time_written
                }
            }
            output = _format_ready_json_success(
                command="ready read-status",
                device_address=address,
                result=result,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.echo(f"\nDevice: {address}")
            click.echo(f"Version: {status.version_string}")
            click.echo(f"Mode: {status.mode_string}")
            click.echo(f"Key Written: {'Yes' if status.key_written else 'No'}")
            click.echo(f"Config Written: {'Yes' if status.config_written else 'No'}")
            click.echo(f"Time Written: {'Yes' if status.epoch_time_written else 'No'}")

        sys.exit(0)

    except BleError as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        if use_json:
            output = _format_ready_json_error(
                command="ready read-status",
                device_address=address,
                error=e,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.secho(f"\n[ERROR] {e}", fg="red", err=True)
        sys.exit(2)
```

**Acceptance Criteria**:
- [ ] `read_status()` function in ready.py connects and reads Status characteristic
- [ ] Function returns `StatusCharacteristic` dataclass
- [ ] CLI command `ready read-status` requires `--address` parameter
- [ ] JSON output matches specification format with version and flags objects
- [ ] Tabular output displays version, mode, and flags in human-readable format
- [ ] BleError raised and formatted correctly on connection failure
- [ ] Exit code 0 on success, 2 on error
- [ ] Duration tracking works correctly
- [ ] Typecheck passes: `mypy src/hubblenetwork/ready.py src/hubblenetwork/cli.py`
- [ ] Lint passes: `ruff check src/hubblenetwork/`

**Testing**:
```bash
# Manual test with real device
hubblenetwork ready read-status --address AA:BB:CC:DD:EE:FF --format json

# Verify JSON structure
hubblenetwork ready read-status --address AA:BB:CC:DD:EE:FF --format json | jq '.result.version, .result.flags'

# Test error handling (invalid address)
hubblenetwork ready read-status --address 00:00:00:00:00:00 --format json

# Verify exit code
hubblenetwork ready read-status --address 00:00:00:00:00:00 --format json; echo "Exit: $?"

# Unit tests
pytest tests/test_ready.py::test_read_status -v
pytest tests/test_cli_ready.py::test_ready_read_status_command -v
```

---

### US-008: Implement ready read-key-info command

**Persona**: Firmware developer testing encryption mode detection

**Description**: As a firmware developer, I want to read the Device Key characteristic to determine encryption mode so that I can verify the device advertises the correct AES mode during testing.

**Business Value**: Enables verification of encryption mode configuration without full provisioning.

**Dependencies**: US-001, US-003, US-004, US-005, US-006

**Implementation Details**:

*File: src/hubblenetwork/ready.py*

Add after `read_status()` function:

```python
async def _read_key_info_async(address: str, timeout: float = 30.0) -> DeviceKeyInfo:
    """
    Async implementation: Connect and read Device Key Info characteristic.

    Reads the single-byte encryption mode indicator from the device.

    Args:
        address: BLE MAC address
        timeout: Connection timeout in seconds

    Returns:
        DeviceKeyInfo with encryption mode

    Raises:
        BleError: If connection or read fails
    """
    from .errors import BleError, extract_att_error_code
    from bleak.exc import BleakError as BleakException

    try:
        async with BleakClient(address, timeout=timeout) as client:
            data = await client.read_gatt_char(CHAR_DEVICE_KEY_UUID)
            return DeviceKeyInfo.from_bytes(bytes(data))
    except BleakException as e:
        att_code = extract_att_error_code(e)
        raise BleError(f"Failed to read Device Key Info: {e}", att_error_code=att_code)
    except Exception as e:
        raise BleError(f"Failed to read Device Key Info: {e}")


def read_key_info(address: str, timeout: float = 30.0) -> DeviceKeyInfo:
    """
    Connect to device and read Device Key Info characteristic.

    Args:
        address: BLE MAC address
        timeout: Connection timeout in seconds

    Returns:
        DeviceKeyInfo with encryption mode

    Raises:
        BleError: If connection or read fails
    """
    try:
        return asyncio.run(_read_key_info_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_read_key_info_async(address, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
```

*File: src/hubblenetwork/cli.py*

Add after `ready_read_status` command:

```python
@ready.command("read-key-info")
@click.option(
    "--address",
    type=str,
    required=True,
    help="BLE MAC address of device",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_read_key_info(address: str, timeout: float = 30.0, output_format: str = "tabular") -> None:
    """
    Read Device Key Info characteristic to determine encryption mode.

    Reads the encryption mode indicator (AES-256-CTR or AES-128-CTR)
    from the device without performing any writes.

    Example:
      hubblenetwork ready read-key-info --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready read-key-info --address AA:BB:CC:DD:EE:FF --format json
    """
    import time
    from hubblenetwork.errors import BleError

    use_json = output_format.lower() == "json"
    start = time.monotonic()

    try:
        key_info = ready_mod.read_key_info(address=address, timeout=timeout)
        duration_ms = int((time.monotonic() - start) * 1000)

        if use_json:
            mode_code = "0x01" if key_info.encryption_mode == "AES-256-CTR" else "0x02"
            result = {
                "encryption_mode": key_info.encryption_mode,
                "encryption_mode_code": mode_code,
                "key_size_bytes": key_info.key_size
            }
            output = _format_ready_json_success(
                command="ready read-key-info",
                device_address=address,
                result=result,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.echo(f"\nDevice: {address}")
            click.echo(f"Encryption Mode: {key_info.encryption_mode}")
            click.echo(f"Key Size: {key_info.key_size} bytes")

        sys.exit(0)

    except BleError as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        if use_json:
            output = _format_ready_json_error(
                command="ready read-key-info",
                device_address=address,
                error=e,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.secho(f"\n[ERROR] {e}", fg="red", err=True)
        sys.exit(2)
```

**Acceptance Criteria**:
- [ ] `read_key_info()` function in ready.py reads Device Key characteristic
- [ ] Function returns `DeviceKeyInfo` dataclass
- [ ] CLI command requires `--address` parameter
- [ ] JSON output includes encryption_mode, encryption_mode_code, key_size_bytes
- [ ] Tabular output displays encryption mode and key size
- [ ] Correctly identifies AES-256-CTR (0x01) and AES-128-CTR (0x02)
- [ ] BleError raised on connection failure
- [ ] Exit code 0 on success, 2 on error
- [ ] Typecheck passes
- [ ] Lint passes

**Testing**:
```bash
# Manual test
hubblenetwork ready read-key-info --address AA:BB:CC:DD:EE:FF --format json

# Verify encryption mode parsing
hubblenetwork ready read-key-info --address AA:BB:CC:DD:EE:FF --format json | jq '.result.encryption_mode'

# Unit tests
pytest tests/test_ready.py::test_read_key_info -v
pytest tests/test_cli_ready.py::test_ready_read_key_info_command -v
```

---

### US-009: Implement ready read-config command

**Persona**: Firmware developer testing configuration characteristic

**Description**: As a firmware developer, I want to read the Device Configuration characteristic so that I can verify EID type and pool size settings without running full provisioning.

**Business Value**: Enables isolated testing of configuration characteristic implementation.

**Dependencies**: US-001, US-003, US-004, US-005, US-006

**Implementation Details**:

*File: src/hubblenetwork/ready.py*

Add new dataclass after `DeviceKeyInfo` (around line 286):

```python
@dataclass(frozen=True)
class DeviceConfig:
    """Parsed Device Configuration characteristic (0x0004) read data."""

    eid_type: str  # "utc" or "counter"
    rotation_period: int  # Must be 0 per spec
    pool_size: int  # For counter mode, 0 for UTC mode
    raw_bytes: bytes  # Original 12-byte data

    @classmethod
    def from_bytes(cls, data: bytes) -> "DeviceConfig":
        """Parse Device Configuration from raw bytes."""
        if len(data) < 12:
            raise ValueError(f"Device Config data too short: {len(data)} bytes, need 12")

        eid_type_byte = data[0]
        eid_type = "utc" if eid_type_byte == 0x00 else "counter" if eid_type_byte == 0x01 else f"unknown-{eid_type_byte:02x}"

        rotation_period = int.from_bytes(data[1:5], byteorder="little")
        pool_size = int.from_bytes(data[5:7], byteorder="little")

        return cls(
            eid_type=eid_type,
            rotation_period=rotation_period,
            pool_size=pool_size,
            raw_bytes=data
        )

    def to_display_string(self) -> str:
        """Human-readable string representation."""
        lines = [
            f"EID Type: {self.eid_type}",
            f"Rotation Period: {self.rotation_period}",
        ]
        if self.eid_type == "counter":
            lines.append(f"Pool Size: {self.pool_size}")
        return "\n".join(lines)
```

Add async function after `read_key_info()`:

```python
async def _read_config_async(address: str, timeout: float = 30.0) -> DeviceConfig:
    """
    Async implementation: Connect and read Device Configuration characteristic.

    Args:
        address: BLE MAC address
        timeout: Connection timeout in seconds

    Returns:
        DeviceConfig with parsed configuration

    Raises:
        BleError: If connection or read fails
    """
    from .errors import BleError, extract_att_error_code
    from bleak.exc import BleakError as BleakException

    try:
        async with BleakClient(address, timeout=timeout) as client:
            data = await client.read_gatt_char(CHAR_DEVICE_CONFIG_UUID)
            return DeviceConfig.from_bytes(bytes(data))
    except BleakException as e:
        att_code = extract_att_error_code(e)
        raise BleError(f"Failed to read Device Config: {e}", att_error_code=att_code)
    except Exception as e:
        raise BleError(f"Failed to read Device Config: {e}")


def read_config(address: str, timeout: float = 30.0) -> DeviceConfig:
    """
    Connect to device and read Device Configuration characteristic.

    Args:
        address: BLE MAC address
        timeout: Connection timeout in seconds

    Returns:
        DeviceConfig with parsed configuration

    Raises:
        BleError: If connection or read fails
    """
    try:
        return asyncio.run(_read_config_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_read_config_async(address, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
```

*File: src/hubblenetwork/cli.py*

Add after `ready_read_key_info` command:

```python
@ready.command("read-config")
@click.option(
    "--address",
    type=str,
    required=True,
    help="BLE MAC address of device",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_read_config(address: str, timeout: float = 30.0, output_format: str = "tabular") -> None:
    """
    Read Device Configuration characteristic from a Hubble Ready device.

    Reads the configuration including EID type (UTC/Counter), rotation period,
    and pool size without modifying the device.

    Example:
      hubblenetwork ready read-config --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready read-config --address AA:BB:CC:DD:EE:FF --format json
    """
    import time
    from hubblenetwork.errors import BleError

    use_json = output_format.lower() == "json"
    start = time.monotonic()

    try:
        config = ready_mod.read_config(address=address, timeout=timeout)
        duration_ms = int((time.monotonic() - start) * 1000)

        if use_json:
            eid_type_code = "0x00" if config.eid_type == "utc" else "0x01" if config.eid_type == "counter" else "0xFF"
            result = {
                "eid_type": config.eid_type,
                "eid_type_code": eid_type_code,
                "rotation_period_seconds": config.rotation_period,
                "pool_size": config.pool_size,
                "raw_bytes": config.raw_bytes.hex()
            }
            output = _format_ready_json_success(
                command="ready read-config",
                device_address=address,
                result=result,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.echo(f"\nDevice: {address}")
            click.echo(config.to_display_string())

        sys.exit(0)

    except BleError as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        if use_json:
            output = _format_ready_json_error(
                command="ready read-config",
                device_address=address,
                error=e,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.secho(f"\n[ERROR] {e}", fg="red", err=True)
        sys.exit(2)
```

**Acceptance Criteria**:
- [ ] `DeviceConfig` dataclass defined with eid_type, rotation_period, pool_size, raw_bytes
- [ ] `read_config()` function reads Device Configuration characteristic
- [ ] CLI command requires `--address` parameter
- [ ] JSON output includes eid_type, eid_type_code, rotation_period_seconds, pool_size, raw_bytes
- [ ] Correctly parses UTC mode (0x00) and Counter mode (0x01)
- [ ] Tabular output displays configuration in human-readable format
- [ ] Exit code 0 on success, 2 on error
- [ ] Typecheck passes
- [ ] Lint passes

**Testing**:
```bash
# Manual test
hubblenetwork ready read-config --address AA:BB:CC:DD:EE:FF --format json

# Verify config parsing
hubblenetwork ready read-config --address AA:BB:CC:DD:EE:FF --format json | jq '.result.eid_type'

# Unit tests
pytest tests/test_ready.py::test_read_config -v
pytest tests/test_cli_ready.py::test_ready_read_config_command -v
```

---

### US-010: Implement ready read-time command

**Persona**: Firmware developer testing epoch time characteristic

**Description**: As a firmware developer, I want to read the Epoch Time characteristic so that I can verify time synchronization without running full provisioning.

**Business Value**: Enables isolated testing of time characteristic implementation.

**Dependencies**: US-001, US-003, US-004, US-005, US-006

**Implementation Details**:

*File: src/hubblenetwork/ready.py*

Add async function after `read_config()`:

```python
async def _read_time_async(address: str, timeout: float = 30.0) -> int:
    """
    Async implementation: Connect and read Epoch Time characteristic.

    Args:
        address: BLE MAC address
        timeout: Connection timeout in seconds

    Returns:
        Unix timestamp as integer (seconds since epoch)

    Raises:
        BleError: If connection or read fails
    """
    from .errors import BleError, extract_att_error_code
    from bleak.exc import BleakError as BleakException

    try:
        async with BleakClient(address, timeout=timeout) as client:
            data = await client.read_gatt_char(CHAR_EPOCH_TIME_UUID)
            data = bytes(data)
            if len(data) < 8:
                raise ValueError(f"Epoch Time data too short: {len(data)} bytes, need 8")
            timestamp = int.from_bytes(data[0:8], byteorder="little")
            return timestamp
    except BleakException as e:
        att_code = extract_att_error_code(e)
        raise BleError(f"Failed to read Epoch Time: {e}", att_error_code=att_code)
    except Exception as e:
        raise BleError(f"Failed to read Epoch Time: {e}")


def read_time(address: str, timeout: float = 30.0) -> int:
    """
    Connect to device and read Epoch Time characteristic.

    Args:
        address: BLE MAC address
        timeout: Connection timeout in seconds

    Returns:
        Unix timestamp as integer (seconds since epoch)

    Raises:
        BleError: If connection or read fails
    """
    try:
        return asyncio.run(_read_time_async(address, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_read_time_async(address, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
```

*File: src/hubblenetwork/cli.py*

Add after `ready_read_config` command:

```python
@ready.command("read-time")
@click.option(
    "--address",
    type=str,
    required=True,
    help="BLE MAC address of device",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_read_time(address: str, timeout: float = 30.0, output_format: str = "tabular") -> None:
    """
    Read Epoch Time characteristic from a Hubble Ready device.

    Reads the current epoch time setting from the device. Returns
    the Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).

    Example:
      hubblenetwork ready read-time --address AA:BB:CC:DD:EE:FF
      hubblenetwork ready read-time --address AA:BB:CC:DD:EE:FF --format json
    """
    import time
    from datetime import datetime, timezone
    from hubblenetwork.errors import BleError

    use_json = output_format.lower() == "json"
    start = time.monotonic()

    try:
        timestamp = ready_mod.read_time(address=address, timeout=timeout)
        duration_ms = int((time.monotonic() - start) * 1000)

        # Convert to ISO 8601 format
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        timestamp_iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        if use_json:
            result = {
                "timestamp": timestamp,
                "timestamp_iso": timestamp_iso,
            }
            output = _format_ready_json_success(
                command="ready read-time",
                device_address=address,
                result=result,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.echo(f"\nDevice: {address}")
            click.echo(f"Timestamp: {timestamp}")
            click.echo(f"Time: {timestamp_iso}")
            click.echo(f"Human: {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        sys.exit(0)

    except BleError as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        if use_json:
            output = _format_ready_json_error(
                command="ready read-time",
                device_address=address,
                error=e,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.secho(f"\n[ERROR] {e}", fg="red", err=True)
        sys.exit(2)
```

**Acceptance Criteria**:
- [ ] `read_time()` function reads Epoch Time characteristic
- [ ] Function returns Unix timestamp as integer
- [ ] CLI command requires `--address` parameter
- [ ] JSON output includes timestamp and timestamp_iso (ISO 8601 format)
- [ ] Tabular output displays timestamp in multiple formats
- [ ] Correctly handles 8-byte little-endian timestamp
- [ ] Exit code 0 on success, 2 on error
- [ ] Typecheck passes
- [ ] Lint passes

**Testing**:
```bash
# Manual test
hubblenetwork ready read-time --address AA:BB:CC:DD:EE:FF --format json

# Verify time parsing
hubblenetwork ready read-time --address AA:BB:CC:DD:EE:FF --format json | jq '.result.timestamp, .result.timestamp_iso'

# Unit tests
pytest tests/test_ready.py::test_read_time -v
pytest tests/test_cli_ready.py::test_ready_read_time_command -v
```

---

### US-011: Implement ready write-key command

**Persona**: Firmware developer testing key write operations

**Description**: As a firmware developer, I want to write an encryption key to the Device Key characteristic so that I can test key write handling in isolation from full provisioning.

**Business Value**: Enables isolated testing of key write logic and error handling.

**Dependencies**: US-001, US-003, US-004, US-005, US-006, US-008 (must read key info first to determine expected size)

**Implementation Details**:

*File: src/hubblenetwork/ready.py*

Add async function after `read_time()`:

```python
async def _write_key_async(
    address: str,
    key: bytes,
    timeout: float = 30.0
) -> WriteResult:
    """
    Async implementation: Write encryption key to Device Key characteristic.

    Automatically reads encryption mode first to validate key length.

    Args:
        address: BLE MAC address
        key: Raw key bytes (16 or 32 bytes depending on device mode)
        timeout: Connection timeout in seconds

    Returns:
        WriteResult with success status
    """
    from .errors import BleError, extract_att_error_code
    from bleak.exc import BleakError as BleakException
    import time

    start = time.monotonic()

    try:
        async with BleakClient(address, timeout=timeout) as client:
            # First read encryption mode to validate key length
            key_info_data = await client.read_gatt_char(CHAR_DEVICE_KEY_UUID)
            key_info = DeviceKeyInfo.from_bytes(bytes(key_info_data))
            expected_size = key_info.key_size

            # Validate key length
            if len(key) != expected_size:
                return WriteResult(
                    success=False,
                    characteristic_name="Device Key",
                    error_code=0x0D,  # Invalid Attribute Value Length
                    error_message=f"Key length mismatch: device expects {expected_size} bytes, provided {len(key)} bytes",
                    duration_ms=int((time.monotonic() - start) * 1000)
                )

            # Write the key
            await client.write_gatt_char(CHAR_DEVICE_KEY_UUID, key)

            duration_ms = int((time.monotonic() - start) * 1000)
            return WriteResult(
                success=True,
                characteristic_name="Device Key",
                duration_ms=duration_ms
            )

    except BleakException as e:
        att_code = extract_att_error_code(e)
        duration_ms = int((time.monotonic() - start) * 1000)
        return WriteResult(
            success=False,
            characteristic_name="Device Key",
            error_code=att_code,
            error_message=str(e),
            duration_ms=duration_ms
        )
    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        return WriteResult(
            success=False,
            characteristic_name="Device Key",
            error_message=str(e),
            duration_ms=duration_ms
        )


def write_key(address: str, key: bytes, timeout: float = 30.0) -> WriteResult:
    """
    Connect to device and write encryption key to Device Key characteristic.

    Automatically validates key length matches device's encryption mode.

    Args:
        address: BLE MAC address
        key: Raw key bytes (16 or 32 bytes)
        timeout: Connection timeout in seconds

    Returns:
        WriteResult with success status and error details if failed
    """
    try:
        return asyncio.run(_write_key_async(address, key, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_write_key_async(address, key, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
```

*File: src/hubblenetwork/cli.py*

Add after `ready_read_time` command:

```python
@ready.command("write-key")
@click.option(
    "--address",
    type=str,
    required=True,
    help="BLE MAC address of device",
)
@click.option(
    "--key",
    type=str,
    required=True,
    help="Encryption key (base64-encoded, 16 or 32 bytes)",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_write_key(
    address: str,
    key: str,
    timeout: float = 30.0,
    output_format: str = "tabular"
) -> None:
    """
    Write encryption key to Device Key characteristic.

    Automatically detects device encryption mode and validates key length
    before attempting write. Key must be base64-encoded.

    Example:
      hubblenetwork ready write-key --address AA:BB:CC:DD:EE:FF --key "AAAA...AAA=" --format json
    """
    import time
    import base64
    from hubblenetwork.errors import BleError

    use_json = output_format.lower() == "json"
    start = time.monotonic()

    # Decode base64 key
    try:
        key_bytes = base64.b64decode(key)
    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        if use_json:
            error = BleError(f"Invalid base64 key: {e}")
            output = _format_ready_json_error(
                command="ready write-key",
                device_address=address,
                error=error,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.secho(f"\n[ERROR] Invalid base64 key: {e}", fg="red", err=True)
        sys.exit(2)

    try:
        result = ready_mod.write_key(address=address, key=key_bytes, timeout=timeout)
        duration_ms = int((time.monotonic() - start) * 1000)

        if result.success:
            if use_json:
                result_data = {
                    "key_written": True,
                    "key_size_bytes": len(key_bytes)
                }
                output = _format_ready_json_success(
                    command="ready write-key",
                    device_address=address,
                    result=result_data,
                    duration_ms=duration_ms
                )
                click.echo(output)
            else:
                click.secho(f"\n[SUCCESS] Key written successfully", fg="green")
                click.echo(f"Key Size: {len(key_bytes)} bytes")
            sys.exit(0)
        else:
            # Write failed - format error
            if use_json:
                error_dict = {
                    "code": f"0x{result.error_code:02X}" if result.error_code else None,
                    "name": ATT_ERROR_NAMES.get(result.error_code, "Write Failed") if result.error_code else "Write Failed",
                    "message": result.error_message
                }
                output = json.dumps({
                    "success": False,
                    "command": "ready write-key",
                    "device": {"address": address},
                    "error": error_dict,
                    "duration_ms": duration_ms
                }, indent=2)
                click.echo(output)
            else:
                click.secho(f"\n[ERROR] Key write failed: {result.error_message}", fg="red", err=True)
            sys.exit(1)

    except BleError as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        if use_json:
            output = _format_ready_json_error(
                command="ready write-key",
                device_address=address,
                error=e,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.secho(f"\n[ERROR] {e}", fg="red", err=True)
        sys.exit(2)
```

**Acceptance Criteria**:
- [ ] `write_key()` function writes encryption key to device
- [ ] Function automatically reads encryption mode first to validate key length
- [ ] Returns `WriteResult` with success status
- [ ] CLI command requires `--address` and `--key` parameters
- [ ] Key parameter is base64-encoded
- [ ] JSON output includes key_written flag and key_size_bytes on success
- [ ] JSON output includes ATT error code and message on failure
- [ ] Exit code 0 on success, 1 on write failure (wrong length), 2 on connection error
- [ ] Typecheck passes
- [ ] Lint passes

**Testing**:
```bash
# Generate test key (32 bytes for AES-256-CTR)
TEST_KEY=$(python3 -c "import base64; print(base64.b64encode(b'A'*32).decode())")

# Manual test
hubblenetwork ready write-key --address AA:BB:CC:DD:EE:FF --key "$TEST_KEY" --format json

# Test wrong key length (should fail with 0x0D)
WRONG_KEY=$(python3 -c "import base64; print(base64.b64encode(b'A'*16).decode())")
hubblenetwork ready write-key --address AA:BB:CC:DD:EE:FF --key "$WRONG_KEY" --format json

# Verify exit codes
hubblenetwork ready write-key --address AA:BB:CC:DD:EE:FF --key "$TEST_KEY" --format json; echo "Exit: $?"
hubblenetwork ready write-key --address AA:BB:CC:DD:EE:FF --key "$WRONG_KEY" --format json; echo "Exit: $?"

# Unit tests
pytest tests/test_ready.py::test_write_key -v
pytest tests/test_cli_ready.py::test_ready_write_key_command -v
```

---

### US-012: Implement ready write-config command

**Persona**: Firmware developer testing configuration write operations

**Description**: As a firmware developer, I want to write device configuration (EID type, pool size) so that I can test configuration validation and write handling in isolation.

**Business Value**: Enables isolated testing of configuration write logic and error codes.

**Dependencies**: US-001, US-003, US-004, US-005, US-006

**Implementation Details**:

*File: src/hubblenetwork/ready.py*

Add async function after `write_key()`:

```python
async def _write_config_async(
    address: str,
    eid_type: str,
    pool_size: int,
    rotation_period: int = 0,
    timeout: float = 30.0
) -> WriteResult:
    """
    Async implementation: Write device configuration.

    Args:
        address: BLE MAC address
        eid_type: "utc" or "counter"
        pool_size: Pool size (1-2048 for counter mode, must be 0 for UTC mode)
        rotation_period: Must be 0 per spec
        timeout: Connection timeout in seconds

    Returns:
        WriteResult with success status
    """
    from .errors import BleError, extract_att_error_code, ATT_ERROR_INVALID_POOL_SIZE
    from bleak.exc import BleakError as BleakException
    import time

    start = time.monotonic()

    # Local validation
    if eid_type not in ["utc", "counter"]:
        return WriteResult(
            success=False,
            characteristic_name="Device Configuration",
            error_message=f"Invalid EID type: {eid_type}, must be 'utc' or 'counter'",
            duration_ms=int((time.monotonic() - start) * 1000)
        )

    if rotation_period != 0:
        return WriteResult(
            success=False,
            characteristic_name="Device Configuration",
            error_code=0x85,  # Invalid Rotation Period
            error_message=f"Rotation period must be 0, got {rotation_period}",
            duration_ms=int((time.monotonic() - start) * 1000)
        )

    if eid_type == "counter":
        if pool_size < 1 or pool_size > 2048:
            return WriteResult(
                success=False,
                characteristic_name="Device Configuration",
                error_code=ATT_ERROR_INVALID_POOL_SIZE,
                error_message=f"Pool size must be 1-2048 for Counter mode, got {pool_size}",
                duration_ms=int((time.monotonic() - start) * 1000)
            )

    try:
        async with BleakClient(address, timeout=timeout) as client:
            # Build configuration bytes
            eid_type_byte = 0x00 if eid_type == "utc" else 0x01
            config = DeviceConfiguration(
                eid_type=eid_type_byte,
                rotation_period=rotation_period,
                eid_pool_size=pool_size
            )
            config_bytes = config.to_bytes()

            # Write configuration
            await client.write_gatt_char(CHAR_DEVICE_CONFIG_UUID, config_bytes)

            duration_ms = int((time.monotonic() - start) * 1000)
            return WriteResult(
                success=True,
                characteristic_name="Device Configuration",
                duration_ms=duration_ms
            )

    except BleakException as e:
        att_code = extract_att_error_code(e)
        duration_ms = int((time.monotonic() - start) * 1000)
        return WriteResult(
            success=False,
            characteristic_name="Device Configuration",
            error_code=att_code,
            error_message=str(e),
            duration_ms=duration_ms
        )
    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        return WriteResult(
            success=False,
            characteristic_name="Device Configuration",
            error_message=str(e),
            duration_ms=duration_ms
        )


def write_config(
    address: str,
    eid_type: str,
    pool_size: int,
    rotation_period: int = 0,
    timeout: float = 30.0
) -> WriteResult:
    """
    Connect to device and write device configuration.

    Args:
        address: BLE MAC address
        eid_type: "utc" or "counter"
        pool_size: Pool size (1-2048 for counter mode)
        rotation_period: Must be 0 per spec
        timeout: Connection timeout in seconds

    Returns:
        WriteResult with success status
    """
    try:
        return asyncio.run(_write_config_async(address, eid_type, pool_size, rotation_period, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(
                    _write_config_async(address, eid_type, pool_size, rotation_period, timeout)
                )
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
```

*File: src/hubblenetwork/cli.py*

Add after `ready_write_key` command:

```python
@ready.command("write-config")
@click.option(
    "--address",
    type=str,
    required=True,
    help="BLE MAC address of device",
)
@click.option(
    "--eid-type",
    type=click.Choice(["utc", "counter"], case_sensitive=False),
    required=True,
    help="EID type: 'utc' or 'counter'",
)
@click.option(
    "--pool-size",
    type=int,
    default=None,
    help="Pool size (1-2048, required for counter mode)",
)
@click.option(
    "--rotation-period",
    type=int,
    default=0,
    show_default=True,
    help="Rotation period (must be 0 per spec)",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_write_config(
    address: str,
    eid_type: str,
    pool_size: Optional[int],
    rotation_period: int,
    timeout: float,
    output_format: str
) -> None:
    """
    Write device configuration to Device Configuration characteristic.

    EID type can be 'utc' or 'counter'. Pool size is required for counter mode.
    Rotation period must be 0 per specification.

    Example:
      hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type counter --pool-size 100 --format json
      hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type utc --format json
    """
    import time
    from hubblenetwork.errors import BleError, ATT_ERROR_NAMES

    use_json = output_format.lower() == "json"
    start = time.monotonic()

    # Validate pool-size for counter mode
    eid_type_lower = eid_type.lower()
    if eid_type_lower == "counter" and pool_size is None:
        error_msg = "Pool size is required for counter mode (--pool-size)"
        if use_json:
            click.echo(json.dumps({
                "success": False,
                "command": "ready write-config",
                "error": {"message": error_msg}
            }))
        else:
            click.secho(f"\n[ERROR] {error_msg}", fg="red", err=True)
        sys.exit(2)

    # Default pool size for UTC mode
    if pool_size is None:
        pool_size = 0

    try:
        result = ready_mod.write_config(
            address=address,
            eid_type=eid_type_lower,
            pool_size=pool_size,
            rotation_period=rotation_period,
            timeout=timeout
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        if result.success:
            if use_json:
                result_data = {
                    "config_written": True,
                    "eid_type": eid_type_lower,
                    "pool_size": pool_size,
                    "rotation_period": rotation_period
                }
                output = _format_ready_json_success(
                    command="ready write-config",
                    device_address=address,
                    result=result_data,
                    duration_ms=duration_ms
                )
                click.echo(output)
            else:
                click.secho(f"\n[SUCCESS] Configuration written successfully", fg="green")
                click.echo(f"EID Type: {eid_type_lower}")
                click.echo(f"Pool Size: {pool_size}")
                click.echo(f"Rotation Period: {rotation_period}")
            sys.exit(0)
        else:
            # Write failed
            if use_json:
                error_dict = {
                    "code": f"0x{result.error_code:02X}" if result.error_code else None,
                    "name": ATT_ERROR_NAMES.get(result.error_code, "Write Failed") if result.error_code else "Write Failed",
                    "message": result.error_message
                }
                output = json.dumps({
                    "success": False,
                    "command": "ready write-config",
                    "device": {"address": address},
                    "error": error_dict,
                    "duration_ms": duration_ms
                }, indent=2)
                click.echo(output)
            else:
                click.secho(f"\n[ERROR] Config write failed: {result.error_message}", fg="red", err=True)
            sys.exit(1)

    except BleError as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        if use_json:
            output = _format_ready_json_error(
                command="ready write-config",
                device_address=address,
                error=e,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.secho(f"\n[ERROR] {e}", fg="red", err=True)
        sys.exit(2)
```

**Acceptance Criteria**:
- [ ] `write_config()` function writes configuration to device
- [ ] Function validates EID type, pool size, rotation period locally
- [ ] Returns `WriteResult` with success status
- [ ] CLI command requires `--address` and `--eid-type` parameters
- [ ] `--pool-size` required for counter mode
- [ ] JSON output includes config_written, eid_type, pool_size, rotation_period
- [ ] Validation errors return appropriate ATT error codes (0x85, 0x86)
- [ ] Exit code 0 on success, 1 on validation failure, 2 on connection error
- [ ] Typecheck passes
- [ ] Lint passes

**Testing**:
```bash
# Manual test - counter mode
hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type counter --pool-size 100 --format json

# Test UTC mode
hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type utc --format json

# Test validation errors
hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type counter --pool-size 2049 --format json  # Should fail
hubblenetwork ready write-config --address AA:BB:CC:DD:EE:FF --eid-type counter --format json  # Should fail (missing pool-size)

# Unit tests
pytest tests/test_ready.py::test_write_config -v
pytest tests/test_cli_ready.py::test_ready_write_config_command -v
```

---

### US-013: Implement ready write-time command

**Persona**: Firmware developer testing time synchronization

**Description**: As a firmware developer, I want to write epoch time to the device so that I can test time write handling and verify time synchronization in isolation.

**Business Value**: Enables isolated testing of time characteristic write logic.

**Dependencies**: US-001, US-003, US-004, US-005, US-006

**Implementation Details**:

*File: src/hubblenetwork/ready.py*

Add async function after `write_config()`:

```python
async def _write_time_async(
    address: str,
    timestamp: Optional[int] = None,
    timeout: float = 30.0
) -> WriteResult:
    """
    Async implementation: Write epoch time to device.

    Args:
        address: BLE MAC address
        timestamp: Unix timestamp (seconds). If None, uses current time.
        timeout: Connection timeout in seconds

    Returns:
        WriteResult with success status
    """
    from .errors import BleError, extract_att_error_code
    from bleak.exc import BleakError as BleakException
    import time as time_module

    start = time_module.monotonic()

    # Use current time if not provided
    if timestamp is None:
        timestamp = int(time_module.time())

    try:
        async with BleakClient(address, timeout=timeout) as client:
            # Convert timestamp to 8-byte little-endian
            time_bytes = timestamp.to_bytes(8, byteorder="little")

            # Write epoch time
            await client.write_gatt_char(CHAR_EPOCH_TIME_UUID, time_bytes)

            duration_ms = int((time_module.monotonic() - start) * 1000)
            return WriteResult(
                success=True,
                characteristic_name="Epoch Time",
                duration_ms=duration_ms
            )

    except BleakException as e:
        att_code = extract_att_error_code(e)
        duration_ms = int((time_module.monotonic() - start) * 1000)
        return WriteResult(
            success=False,
            characteristic_name="Epoch Time",
            error_code=att_code,
            error_message=str(e),
            duration_ms=duration_ms
        )
    except Exception as e:
        duration_ms = int((time_module.monotonic() - start) * 1000)
        return WriteResult(
            success=False,
            characteristic_name="Epoch Time",
            error_message=str(e),
            duration_ms=duration_ms
        )


def write_time(
    address: str,
    timestamp: Optional[int] = None,
    timeout: float = 30.0
) -> WriteResult:
    """
    Connect to device and write epoch time.

    Args:
        address: BLE MAC address
        timestamp: Unix timestamp (seconds). If None, uses current time.
        timeout: Connection timeout in seconds

    Returns:
        WriteResult with success status
    """
    try:
        return asyncio.run(_write_time_async(address, timestamp, timeout))
    except RuntimeError:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(_write_time_async(address, timestamp, timeout))
            finally:
                loop.close()
        raise RuntimeError(
            "Cannot run synchronous BLE operation inside an existing async event loop."
        )
```

*File: src/hubblenetwork/cli.py*

Add after `ready_write_config` command:

```python
@ready.command("write-time")
@click.option(
    "--address",
    type=str,
    required=True,
    help="BLE MAC address of device",
)
@click.option(
    "--timestamp",
    type=int,
    default=None,
    help="Unix timestamp in seconds (default: current time)",
)
@click.option(
    "--timeout",
    "-t",
    type=float,
    default=30.0,
    show_default=True,
    help="Connection timeout in seconds",
)
@click.option(
    "--format",
    "-o",
    "output_format",
    type=click.Choice(["tabular", "json"], case_sensitive=False),
    default="tabular",
    show_default=True,
    help="Output format",
)
def ready_write_time(
    address: str,
    timestamp: Optional[int],
    timeout: float,
    output_format: str
) -> None:
    """
    Write epoch time to Epoch Time characteristic.

    If timestamp is not provided, uses current system time.
    Timestamp must be Unix timestamp in seconds since epoch.

    Example:
      hubblenetwork ready write-time --address AA:BB:CC:DD:EE:FF --format json
      hubblenetwork ready write-time --address AA:BB:CC:DD:EE:FF --timestamp 1704067200 --format json
    """
    import time
    from datetime import datetime, timezone
    from hubblenetwork.errors import BleError, ATT_ERROR_NAMES

    use_json = output_format.lower() == "json"
    start = time.monotonic()

    try:
        result = ready_mod.write_time(
            address=address,
            timestamp=timestamp,
            timeout=timeout
        )
        duration_ms = int((time.monotonic() - start) * 1000)

        # Get actual timestamp written (may be current time if not specified)
        written_timestamp = timestamp if timestamp is not None else int(time.time())
        dt = datetime.fromtimestamp(written_timestamp, tz=timezone.utc)
        timestamp_iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        if result.success:
            if use_json:
                result_data = {
                    "time_written": True,
                    "timestamp": written_timestamp,
                    "timestamp_iso": timestamp_iso
                }
                output = _format_ready_json_success(
                    command="ready write-time",
                    device_address=address,
                    result=result_data,
                    duration_ms=duration_ms
                )
                click.echo(output)
            else:
                click.secho(f"\n[SUCCESS] Time written successfully", fg="green")
                click.echo(f"Timestamp: {written_timestamp}")
                click.echo(f"Time: {timestamp_iso}")
            sys.exit(0)
        else:
            # Write failed
            if use_json:
                error_dict = {
                    "code": f"0x{result.error_code:02X}" if result.error_code else None,
                    "name": ATT_ERROR_NAMES.get(result.error_code, "Write Failed") if result.error_code else "Write Failed",
                    "message": result.error_message
                }
                output = json.dumps({
                    "success": False,
                    "command": "ready write-time",
                    "device": {"address": address},
                    "error": error_dict,
                    "duration_ms": duration_ms
                }, indent=2)
                click.echo(output)
            else:
                click.secho(f"\n[ERROR] Time write failed: {result.error_message}", fg="red", err=True)
            sys.exit(1)

    except BleError as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        if use_json:
            output = _format_ready_json_error(
                command="ready write-time",
                device_address=address,
                error=e,
                duration_ms=duration_ms
            )
            click.echo(output)
        else:
            click.secho(f"\n[ERROR] {e}", fg="red", err=True)
        sys.exit(2)
```

**Acceptance Criteria**:
- [ ] `write_time()` function writes epoch time to device
- [ ] Function uses current time if timestamp not provided
- [ ] Returns `WriteResult` with success status
- [ ] CLI command requires `--address` parameter
- [ ] `--timestamp` is optional (defaults to current time)
- [ ] JSON output includes time_written, timestamp, timestamp_iso
- [ ] Timestamp is 8-byte little-endian format
- [ ] Exit code 0 on success, 1 on write failure, 2 on connection error
- [ ] Typecheck passes
- [ ] Lint passes

**Testing**:
```bash
# Manual test with current time
hubblenetwork ready write-time --address AA:BB:CC:DD:EE:FF --format json

# Test with specific timestamp
hubblenetwork ready write-time --address AA:BB:CC:DD:EE:FF --timestamp 1704067200 --format json

# Verify time was written
hubblenetwork ready read-time --address AA:BB:CC:DD:EE:FF --format json

# Unit tests
pytest tests/test_ready.py::test_write_time -v
pytest tests/test_cli_ready.py::test_ready_write_time_command -v
```

---

## 5. Implementation Progress Tracking

After implementing each story:

1. Mark acceptance criteria as complete
2. Run all specified tests
3. Verify typecheck and lint pass
4. Commit changes with reference to story ID (e.g., "feat: implement US-007 ready read-status command")
5. Move to next story in dependency order

---

## 6. Testing Strategy

### 6.1 Unit Tests

Create test files:
- `tests/test_ready_dataclasses.py` - Test WriteResult, TestResult, ValidationResult
- `tests/test_ready_functions.py` - Test async/sync read/write functions
- `tests/test_cli_ready_commands.py` - Test CLI commands with CliRunner

### 6.2 Integration Tests

Requires physical hardware or mock BLE adapter:
- Test full command execution with real/mocked devices
- Verify JSON output parsing
- Verify exit codes

### 6.3 Manual Testing

After each story implementation:
```bash
# Typecheck
mypy src/hubblenetwork/

# Lint
ruff check src/hubblenetwork/

# Run unit tests
pytest tests/ -v

# Manual CLI test
hubblenetwork ready [command] --help
```

---

## 7. Future Stories (Not in MVP)

The following stories are defined in the specification but marked as future enhancements:

- **US-014**: Implement `ready validate` command (10 read-only tests)
- **US-015**: Implement `ready test` command (15 tests including writes)
- **US-016**: Implement `ready test-errors` command (8 error scenarios)
- **US-017**: Add `--address` to `ready provision` command

These will be implemented after core granular commands (US-001 through US-013) are complete and tested.

---

## Appendix A: Command Reference

| Command | Purpose | Parameters | Exit Codes |
|---------|---------|------------|------------|
| `ready scan` | Scan for devices | --timeout, --address, --format | 0=success, 2=error |
| `ready info` | Show characteristics | --timeout, --address, --format | 0=success, 2=error |
| `ready read-status` | Read Status | --address, --timeout, --format | 0=success, 2=error |
| `ready read-key-info` | Read Key Info | --address, --timeout, --format | 0=success, 2=error |
| `ready read-config` | Read Config | --address, --timeout, --format | 0=success, 2=error |
| `ready read-time` | Read Time | --address, --timeout, --format | 0=success, 2=error |
| `ready write-key` | Write Key | --address, --key, --timeout, --format | 0=success, 1=fail, 2=error |
| `ready write-config` | Write Config | --address, --eid-type, --pool-size, --timeout, --format | 0=success, 1=fail, 2=error |
| `ready write-time` | Write Time | --address, --timestamp, --timeout, --format | 0=success, 1=fail, 2=error |

---

## Appendix B: ATT Error Codes

| Code | Hex | Name | Usage |
|------|-----|------|-------|
| 13 | 0x0D | Invalid Attribute Value Length | Wrong write payload size |
| 15 | 0x0F | Insufficient Encryption | Link not encrypted |
| 132 | 0x84 | Invalid EID Type | EID type not 0x00 or 0x01 |
| 133 | 0x85 | Invalid Rotation Period | Rotation period not 0 |
| 134 | 0x86 | Invalid Pool Size | Pool size not 1-2048 |
| 135 | 0x87 | Invalid Reserved Field | Reserved bytes not zero |

---

**END OF PRD**
