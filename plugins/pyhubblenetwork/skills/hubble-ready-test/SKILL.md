---
name: hubble-ready-test
description: |
  Testing framework for Hubble Ready devices over Bluetooth Low Energy (BLE).
  Use when testing Hubble Ready device functionality, validating BLE connectivity,
  verifying device characteristics, testing encryption key writes, validating
  configuration updates, or debugging provisioning workflows. Provides structured
  test commands with JSON output for automated validation.
allowed-tools: Bash(hubblenetwork ready *)
disable-model-invocation: false
user-invocable: true
---

# Hubble Ready Testing Framework

## Overview

This testing framework provides comprehensive validation capabilities for Hubble Ready devices over Bluetooth Low Energy (BLE). It wraps the `hubblenetwork ready` CLI commands to enable systematic testing of device discovery, characteristic reads/writes, and the complete provisioning workflow.

The framework is designed for:
- **Device validation** - Verify BLE connectivity and device characteristics
- **Encryption testing** - Validate key writes and encryption mode detection
- **Configuration testing** - Test EID configuration updates
- **Time synchronization testing** - Verify device time reads/writes
- **Integration testing** - Execute and validate the complete provisioning flow
- **Debugging** - Diagnose BLE connection issues and ATT protocol errors

## Test Prerequisites

### BLE Adapter Requirements

- **macOS**: CoreBluetooth (must run in GUI session, not SSH)
- **Linux**: BlueZ stack (user must be in `bluetooth` group)
- **Windows**: Compatible BLE stack with Windows Runtime support

### Permissions

- **macOS**: Bluetooth permission granted to Terminal/iTerm
- **Linux**: User in `bluetooth` group: `sudo usermod -a -G bluetooth $USER`
- **Windows**: Administrator privileges may be required

### Environment Variables (for provisioning tests)

```bash
export HUBBLE_ORG_ID="your-org-id"
export HUBBLE_API_TOKEN="your-api-token"
```

These are only required for the `provision` command which registers devices with the Hubble backend.

## Available Test Commands

All test commands support `--format json` for structured output suitable for automated validation. Always use JSON format for testing to enable programmatic result verification.

### Discovery Tests

#### Test: Device Discovery (`scan`)

Scan for Hubble Ready devices advertising the 0xFCA7 service UUID.

**Command:**
```bash
hubblenetwork ready scan --format json [--timeout SECONDS]
```

**Parameters:**
- `--timeout` (optional): Scan duration in seconds (default: 10)
- `--format json`: Required for structured output

**Expected Output:**
```json
{
  "devices": [
    {
      "address": "AA:BB:CC:DD:EE:FF",
      "name": "Hubble Ready Device",
      "rssi": -65
    }
  ],
  "scan_duration": 10.2
}
```

**Validation:**
- Verify `devices` array is not empty
- Verify MAC addresses are valid format (XX:XX:XX:XX:XX:XX)
- Verify RSSI values are negative integers
- Verify scan_duration matches timeout parameter

**Common Test Failures:**
- Empty devices array: Device not in range or not advertising
- "Bluetooth adapter not found": BLE adapter not available
- Permission denied: Insufficient BLE permissions

---

#### Test: Device Information (`info`)

Read all characteristics from a connected Hubble Ready device.

**Command:**
```bash
hubblenetwork ready info --format json --address <MAC> [--timeout SECONDS]
```

**Parameters:**
- `--address` (required): Device MAC address from scan
- `--timeout` (optional): Connection timeout in seconds (default: 10)
- `--format json`: Required for structured output

**Expected Output:**
```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "status": {
    "firmware_version": "1.2.3",
    "key_written": false,
    "config_written": false,
    "time_written": false
  },
  "key_info": {
    "encryption_mode": "AES-256-CTR"
  },
  "config": {
    "eid_type": "utc",
    "rotation_period_seconds": 900,
    "pool_size": 5
  },
  "time": {
    "unix_timestamp": 1709424000,
    "datetime": "2024-03-03T00:00:00Z"
  }
}
```

**Validation:**
- Verify all four characteristic groups present
- Verify firmware_version format (semantic version)
- Verify encryption_mode is "AES-128-CTR" or "AES-256-CTR"
- Verify eid_type is "utc" or "counter"
- Verify unix_timestamp is reasonable (not 0, not far future)

**Common Test Failures:**
- Connection timeout: Device out of range or BLE interference
- "Device not found": Invalid MAC address
- Incomplete characteristics: Device may not be fully provisioned

---

### Read Validation Tests

All read tests require the `--address` flag and support `--timeout`.

#### Test: Status Read (`read-status`)

Read firmware version and provisioning status flags.

**Command:**
```bash
hubblenetwork ready read-status --format json --address <MAC> [--timeout SECONDS]
```

**Expected Output:**
```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "firmware_version": "1.2.3",
  "key_written": false,
  "config_written": false,
  "time_written": false
}
```

**Validation:**
- Verify firmware_version is non-empty string
- Verify all boolean flags are present
- Use flags to determine provisioning state

**Test Scenarios:**
- Fresh device: All flags false
- Partially provisioned: Some flags true
- Fully provisioned: All flags true

---

#### Test: Key Info Read (`read-key-info`)

Read encryption mode to determine required key size.

**Command:**
```bash
hubblenetwork ready read-key-info --format json --address <MAC> [--timeout SECONDS]
```

**Expected Output:**
```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "encryption_mode": "AES-256-CTR"
}
```

**Validation:**
- Verify encryption_mode is either "AES-128-CTR" or "AES-256-CTR"
- Use this to determine key size for write-key tests (16 or 32 bytes)

**Test Note:**
Always read key info before testing key writes to ensure correct key size.

---

#### Test: Config Read (`read-config`)

Read EID configuration parameters.

**Command:**
```bash
hubblenetwork ready read-config --format json --address <MAC> [--timeout SECONDS]
```

**Expected Output:**
```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "eid_type": "utc",
  "rotation_period_seconds": 900,
  "pool_size": 5
}
```

**Validation:**
- Verify eid_type is "utc" or "counter"
- Verify rotation_period_seconds > 0
- Verify pool_size >= 1
- Default values: eid_type="utc", rotation_period=900, pool_size=5

---

#### Test: Time Read (`read-time`)

Read device's current Unix timestamp.

**Command:**
```bash
hubblenetwork ready read-time --format json --address <MAC> [--timeout SECONDS]
```

**Expected Output:**
```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "unix_timestamp": 1709424000,
  "datetime": "2024-03-03T00:00:00Z"
}
```

**Validation:**
- Verify unix_timestamp is positive integer
- Verify unix_timestamp is reasonable (after 2020, before far future)
- Calculate drift: `abs(device_time - system_time)`
- If drift > 60 seconds, consider time sync test

---

### Write Validation Tests

All write tests require the `--address` flag and return success confirmation.

#### Test: Key Write (`write-key`)

Write base64-encoded encryption key to device.

**Command:**
```bash
hubblenetwork ready write-key --format json --address <MAC> --key <BASE64_KEY> [--timeout SECONDS]
```

**Parameters:**
- `--address` (required): Device MAC address
- `--key` (required): Base64-encoded key (16 bytes for AES-128, 32 bytes for AES-256)
- `--timeout` (optional): Connection timeout in seconds (default: 10)

**Expected Output:**
```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "success": true,
  "message": "Encryption key written successfully"
}
```

**Test Workflow:**
1. Read encryption mode: `read-key-info`
2. Generate key with correct size (16 or 32 bytes)
3. Base64 encode key
4. Write key
5. Verify: Read status and check `key_written` flag

**Key Generation Example:**
```bash
# For AES-128-CTR (16 bytes)
KEY=$(openssl rand -base64 16)

# For AES-256-CTR (32 bytes)
KEY=$(openssl rand -base64 32)

hubblenetwork ready write-key --format json --address <MAC> --key "$KEY"
```

**Common Test Failures:**
- ATT error 0x0D (Invalid Attribute Value Length): Wrong key size
- ATT error 0x0E (Unlikely Error): Device rejected write
- "Invalid base64": Key not properly encoded

---

#### Test: Config Write (`write-config`)

Write EID configuration to device.

**Command:**
```bash
hubblenetwork ready write-config --format json --address <MAC> --eid-type <TYPE> --pool-size <SIZE> [--timeout SECONDS]
```

**Parameters:**
- `--address` (required): Device MAC address
- `--eid-type` (required): "utc" or "counter"
- `--pool-size` (required): Integer >= 1
- `--timeout` (optional): Connection timeout in seconds (default: 10)

**Expected Output:**
```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "success": true,
  "message": "Configuration written successfully"
}
```

**Test Workflow:**
1. Read current config: `read-config`
2. Write new config with different values
3. Verify: Read config again and confirm changes

**Test Examples:**
```bash
# Test UTC mode with pool size 10
hubblenetwork ready write-config --format json --address <MAC> --eid-type utc --pool-size 10

# Test counter mode with pool size 1
hubblenetwork ready write-config --format json --address <MAC> --eid-type counter --pool-size 1
```

**Validation:**
- Verify success: true
- Read config after write and compare values
- Test boundary conditions (pool-size=1, large pool-size)

---

#### Test: Time Write (`write-time`)

Write Unix timestamp to device (defaults to current time if not specified).

**Command:**
```bash
hubblenetwork ready write-time --format json --address <MAC> [--timestamp UNIX_TS] [--timeout SECONDS]
```

**Parameters:**
- `--address` (required): Device MAC address
- `--timestamp` (optional): Unix timestamp (default: current time)
- `--timeout` (optional): Connection timeout in seconds (default: 10)

**Expected Output:**
```json
{
  "address": "AA:BB:CC:DD:EE:FF",
  "success": true,
  "message": "Time written successfully",
  "timestamp_written": 1709424000
}
```

**Test Workflow:**
1. Read device time: `read-time`
2. Calculate drift from system time
3. If drift significant, write current time
4. Verify: Read time again and confirm sync

**Test Examples:**
```bash
# Write current time
hubblenetwork ready write-time --format json --address <MAC>

# Write specific timestamp
hubblenetwork ready write-time --format json --address <MAC> --timestamp 1709424000
```

**Validation:**
- Verify success: true
- Read time after write
- Verify new time matches expected value (+/- a few seconds)

---

### Integration Test

#### Test: Full Provisioning (`provision`)

Execute complete provisioning workflow: scan → register with backend → write key/config/time.

**Command:**
```bash
hubblenetwork ready provision --format json [--timeout SECONDS] [--eid-type TYPE] [--pool-size SIZE]
```

**Parameters:**
- `--timeout` (optional): Per-operation timeout (default: 10)
- `--eid-type` (optional): "utc" or "counter" (default: "utc")
- `--pool-size` (optional): Integer >= 1 (default: 5)

**Environment Variables Required:**
- `HUBBLE_ORG_ID`: Organization ID
- `HUBBLE_API_TOKEN`: API token

**Expected Output:**
```json
{
  "success": true,
  "device": {
    "address": "AA:BB:CC:DD:EE:FF",
    "device_id": "dev_abc123",
    "name": "Hubble Ready Device"
  },
  "steps": {
    "scan": {"success": true, "duration": 5.2},
    "register": {"success": true, "duration": 0.8},
    "write_key": {"success": true, "duration": 2.1},
    "write_config": {"success": true, "duration": 1.9},
    "write_time": {"success": true, "duration": 1.8}
  },
  "total_duration": 11.8
}
```

**Test Workflow:**
1. Environment check: Verify HUBBLE_ORG_ID and HUBBLE_API_TOKEN set
2. Run provisioning
3. Verify all steps succeeded
4. Verify device_id returned
5. Optional: Use `info` command to verify all flags are true

**Validation:**
- Verify success: true
- Verify all steps.*.success: true
- Verify device.device_id is non-empty
- Verify total_duration is reasonable
- Follow-up: Run `read-status` to confirm all flags true

**Common Test Failures:**
- Missing environment variables: Set HUBBLE_ORG_ID and HUBBLE_API_TOKEN
- Backend registration failed: Check credentials validity
- Device selection timeout: Multiple devices found, use --address to specify
- Write failures: Check individual step errors for details

---

## Test Output Format

All commands support `--format json` which returns structured output:

### Success Response
```json
{
  "success": true,
  "data": { /* command-specific data */ },
  "duration": 2.5
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "type": "BleConnectionError",
    "message": "Failed to connect to device",
    "details": "Connection timeout after 10 seconds",
    "att_error_code": 14,
    "att_error_name": "Unlikely Error"
  }
}
```

**Error Fields:**
- `type`: Python exception class name
- `message`: Human-readable error description
- `details`: Additional context
- `att_error_code`: ATT protocol error code (if applicable)
- `att_error_name`: ATT error name (if applicable)

---

## Testing Workflows

### Workflow 1: Device Discovery Validation

**Purpose:** Verify device is advertising and readable.

**Steps:**
1. Scan for devices
2. Verify device found
3. Read device info
4. Validate all characteristics present

**Commands:**
```bash
# Step 1: Scan
hubblenetwork ready scan --format json --timeout 10

# Step 2: Get address from scan output, read info
hubblenetwork ready info --format json --address <MAC>
```

**Expected Results:**
- Scan returns device(s)
- Info command succeeds
- All four characteristic groups present

---

### Workflow 2: Encryption Key Write Validation

**Purpose:** Test encryption key write with correct key size.

**Steps:**
1. Read encryption mode to determine key size
2. Generate key with correct size
3. Write key to device
4. Verify key_written flag is true

**Commands:**
```bash
# Step 1: Read encryption mode
hubblenetwork ready read-key-info --format json --address <MAC>

# Step 2: Generate key (example for AES-256-CTR)
KEY=$(openssl rand -base64 32)

# Step 3: Write key
hubblenetwork ready write-key --format json --address <MAC> --key "$KEY"

# Step 4: Verify
hubblenetwork ready read-status --format json --address <MAC>
```

**Expected Results:**
- read-key-info returns encryption mode
- write-key succeeds
- read-status shows key_written: true

---

### Workflow 3: Configuration Update Validation

**Purpose:** Test configuration write and verify changes persist.

**Steps:**
1. Read current configuration
2. Write new configuration
3. Read configuration again
4. Verify changes applied

**Commands:**
```bash
# Step 1: Read current config
hubblenetwork ready read-config --format json --address <MAC>

# Step 2: Write new config
hubblenetwork ready write-config --format json --address <MAC> --eid-type utc --pool-size 10

# Step 3: Verify changes
hubblenetwork ready read-config --format json --address <MAC>
```

**Expected Results:**
- Initial read succeeds
- Write succeeds
- Final read shows updated values (eid_type=utc, pool_size=10)

---

### Workflow 4: Time Synchronization Validation

**Purpose:** Check device time and synchronize if drift detected.

**Steps:**
1. Read device time
2. Calculate drift from system time
3. If drift > threshold, write current time
4. Verify synchronization

**Commands:**
```bash
# Step 1: Read device time
hubblenetwork ready read-time --format json --address <MAC>

# Step 2: If drift detected, sync time
hubblenetwork ready write-time --format json --address <MAC>

# Step 3: Verify
hubblenetwork ready read-time --format json --address <MAC>
```

**Expected Results:**
- Initial read shows device time
- Write succeeds if needed
- Final read shows synchronized time

---

### Workflow 5: Full Provisioning Integration Test

**Purpose:** Execute complete provisioning flow end-to-end.

**Prerequisites:**
- Environment variables set: HUBBLE_ORG_ID, HUBBLE_API_TOKEN
- Device in range and advertising

**Commands:**
```bash
# Run complete provisioning
hubblenetwork ready provision --format json

# Verify provisioning
hubblenetwork ready info --format json --address <MAC>
```

**Expected Results:**
- Provisioning succeeds with all steps completing
- Info command shows all flags true (key_written, config_written, time_written)
- Device registered in Hubble backend with valid device_id

---

## Test Failure Handling

### BLE Adapter Issues

**Symptom:**
```json
{
  "success": false,
  "error": {
    "type": "BleScanError",
    "message": "Bluetooth adapter not found"
  }
}
```

**Debugging Steps:**
1. Verify BLE adapter is present: `hciconfig` (Linux) or System Preferences (macOS)
2. Check adapter is powered on
3. Verify permissions (see Prerequisites section)

---

### Permission Denied

**Symptom:**
```json
{
  "success": false,
  "error": {
    "type": "BleScanError",
    "message": "Access denied",
    "details": "org.bluez.Error.NotPermitted"
  }
}
```

**Debugging Steps:**
- **macOS**: Must run in GUI session, not SSH. Grant Bluetooth permission to Terminal/iTerm in System Preferences.
- **Linux**: Add user to bluetooth group: `sudo usermod -a -G bluetooth $USER`, then log out and back in.
- **Windows**: Run as Administrator.

---

### Connection Timeout

**Symptom:**
```json
{
  "success": false,
  "error": {
    "type": "BleConnectionError",
    "message": "Failed to connect to device",
    "details": "Connection timeout after 10 seconds"
  }
}
```

**Debugging Steps:**
1. Verify device is in range and advertising: Run scan test
2. Check RSSI value from scan (should be > -80 dBm)
3. Increase timeout: `--timeout 30`
4. Reduce BLE interference (move away from WiFi routers, other BLE devices)
5. Try connecting to device from phone app to verify it's responsive

---

### ATT Protocol Errors

ATT (Attribute Protocol) errors indicate the device rejected the operation.

**ATT Error 0x0E (14): "Unlikely Error"**

Device rejected the operation for internal reasons.

```json
{
  "success": false,
  "error": {
    "type": "BleError",
    "message": "Write failed",
    "att_error_code": 14,
    "att_error_name": "Unlikely Error"
  }
}
```

**Debugging Steps:**
1. Verify device is not already provisioned (check status flags)
2. Try reading the characteristic first to verify it's accessible
3. Power cycle the device
4. Check firmware version supports the operation

---

**ATT Error 0x0D (13): "Invalid Attribute Value Length"**

Wrong data size for characteristic write.

```json
{
  "success": false,
  "error": {
    "type": "BleError",
    "message": "Write failed",
    "att_error_code": 13,
    "att_error_name": "Invalid Attribute Value Length"
  }
}
```

**Debugging Steps:**
1. For key writes: Read encryption mode first, ensure key matches (16 bytes for AES-128, 32 bytes for AES-256)
2. Verify base64 encoding is correct
3. Check key size: `echo "$KEY" | base64 -d | wc -c`

---

### Invalid Key Size

**Symptom:**
```json
{
  "success": false,
  "error": {
    "type": "ValueError",
    "message": "Invalid key size",
    "details": "Key must be 16 bytes for AES-128-CTR or 32 bytes for AES-256-CTR"
  }
}
```

**Debugging Steps:**
1. Read encryption mode: `hubblenetwork ready read-key-info --format json --address <MAC>`
2. Generate correct key size:
   - AES-128-CTR: `openssl rand -base64 16` (16 bytes)
   - AES-256-CTR: `openssl rand -base64 32` (32 bytes)
3. Verify key decodes to correct size: `echo "$KEY" | base64 -d | wc -c`

---

### Device Not Found

**Symptom:**
```json
{
  "success": false,
  "error": {
    "type": "BleConnectionError",
    "message": "Device not found",
    "details": "No device found with address AA:BB:CC:DD:EE:FF"
  }
}
```

**Debugging Steps:**
1. Verify MAC address is correct (check scan output)
2. Verify device is still advertising (run scan again)
3. Check device is powered on and in range
4. Try scanning with longer timeout

---

## Testing Best Practices

### Always Use JSON Format

All test commands should include `--format json` for structured output:

```bash
# ✓ Good - JSON output
hubblenetwork ready scan --format json

# ✗ Bad - Table output (hard to parse)
hubblenetwork ready scan
```

JSON output enables:
- Automated validation and assertions
- Error detail extraction (ATT codes, error types)
- Timing information for performance analysis
- Consistent parsing across all commands

---

### Set Appropriate Timeouts

Default timeout is 10 seconds. Adjust based on test scenario:

```bash
# Quick scan
hubblenetwork ready scan --format json --timeout 5

# Longer scan for weak signal devices
hubblenetwork ready scan --format json --timeout 30

# Connection with BLE interference
hubblenetwork ready info --format json --address <MAC> --timeout 20
```

**Guidelines:**
- Scans: 5-30 seconds depending on device density
- Reads: 10-15 seconds (default usually sufficient)
- Writes: 10-20 seconds (writes may take longer)
- Provisioning: 30+ seconds (multiple operations)

---

### Read Before Write

Always read characteristics before writing to understand current state:

```bash
# ✓ Good - Read first, then write
hubblenetwork ready read-key-info --format json --address <MAC>
# ... determine key size from output ...
hubblenetwork ready write-key --format json --address <MAC> --key "$KEY"

# ✗ Bad - Write without reading (may use wrong key size)
hubblenetwork ready write-key --format json --address <MAC> --key "$KEY"
```

---

### Verify Writes

After write operations, always read back to verify changes persisted:

```bash
# Write config
hubblenetwork ready write-config --format json --address <MAC> --eid-type utc --pool-size 10

# Verify write succeeded
hubblenetwork ready read-config --format json --address <MAC>
# Expected: eid_type="utc", pool_size=10
```

---

### Handle Multiple Devices

When multiple devices are present, always specify `--address`:

```bash
# Scan to find devices
hubblenetwork ready scan --format json

# Specify device for operations
hubblenetwork ready info --format json --address AA:BB:CC:DD:EE:FF
```

For provisioning with multiple devices, the command will prompt for device selection unless `--address` is provided.

---

### Check Status Flags

Use status flags to determine device provisioning state:

```bash
hubblenetwork ready read-status --format json --address <MAC>
```

**Flag Interpretation:**
- `key_written: false` → Need to write encryption key
- `config_written: false` → Need to write configuration
- `time_written: false` → Need to write time
- All `true` → Device fully provisioned

---

### Capture Test Results

For automated testing, capture JSON output for validation:

```bash
# Capture test result
RESULT=$(hubblenetwork ready scan --format json)

# Parse with jq for validation
DEVICE_COUNT=$(echo "$RESULT" | jq '.devices | length')
if [ "$DEVICE_COUNT" -eq 0 ]; then
  echo "TEST FAILED: No devices found"
  exit 1
fi

echo "TEST PASSED: Found $DEVICE_COUNT device(s)"
```

---

## Test Command Reference

Quick reference table for all test commands:

| Command | Purpose | Required Flags | Optional Flags |
|---------|---------|---------------|----------------|
| `scan` | Find devices | `--format json` | `--timeout` |
| `info` | Read all characteristics | `--format json --address` | `--timeout` |
| `read-status` | Read provisioning status | `--format json --address` | `--timeout` |
| `read-key-info` | Read encryption mode | `--format json --address` | `--timeout` |
| `read-config` | Read EID config | `--format json --address` | `--timeout` |
| `read-time` | Read device time | `--format json --address` | `--timeout` |
| `write-key` | Write encryption key | `--format json --address --key` | `--timeout` |
| `write-config` | Write EID config | `--format json --address --eid-type --pool-size` | `--timeout` |
| `write-time` | Write device time | `--format json --address` | `--timeout --timestamp` |
| `provision` | Full provisioning flow | `--format json` | `--timeout --eid-type --pool-size --address` |

---

## Debugging Test Failures

### Diagnostic Commands

When tests fail, use these diagnostic commands:

```bash
# Check BLE adapter status (Linux)
hciconfig
bluetoothctl show

# Check BLE permissions (Linux)
groups | grep bluetooth

# Test basic BLE scanning (Linux)
sudo hcitool lescan

# Check system Bluetooth (macOS)
system_profiler SPBluetoothDataType
```

---

### Common Issues and Solutions

**Issue: "No devices found" but device is on**
- Solution: Increase scan timeout, verify device is in pairing mode, check RSSI levels

**Issue: "Connection refused" repeatedly**
- Solution: Power cycle device, clear Bluetooth cache, try from different host

**Issue: Writes succeed but reads show old values**
- Solution: Device may need power cycle to apply changes, verify write actually succeeded

**Issue: Provisioning fails at registration step**
- Solution: Verify environment variables set, check API token validity, verify network connectivity

**Issue: Intermittent connection failures**
- Solution: Check for BLE interference (WiFi 2.4GHz, other BLE devices), increase timeout, improve signal strength

---

## Source Code References

For implementation details and error codes:

- **CLI Implementation**: `src/hubblenetwork/cli.py` (lines 852-2136)
- **BLE Module**: `src/hubblenetwork/ready.py`
- **Error Codes**: `src/hubblenetwork/errors.py`
- **Crypto Module**: `src/hubblenetwork/crypto.py`

---

## Additional Resources

- **Project README**: `README.md` - SDK overview and installation
- **CLAUDE.md**: `CLAUDE.md` - Architecture and development guide
- **Example Outputs**: `.claude/skills/hubble-ready-test/examples/` - Sample JSON responses

---

## Testing Framework Support

For issues or questions about this testing framework:

1. Check example outputs in `examples/` directory
2. Review debugging section for common failures
3. Verify prerequisites (BLE adapter, permissions)
4. Check source code references for implementation details

The testing framework is a documentation layer that wraps the existing CLI. It stays synchronized with the CLI automatically since it documents exact command syntax.
