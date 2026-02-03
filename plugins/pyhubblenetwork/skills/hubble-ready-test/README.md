# Hubble Ready Testing Framework

A comprehensive testing framework for validating Hubble Ready devices over Bluetooth Low Energy (BLE).

## Overview

This Claude Code skill provides structured testing capabilities for:

- **Device Discovery** - Scan for and validate Hubble Ready devices
- **Characteristic Testing** - Read/write device characteristics (status, key, config, time)
- **Encryption Validation** - Test key writes with correct encryption modes
- **Configuration Testing** - Validate EID configuration updates
- **Provisioning Tests** - Execute and verify the complete provisioning workflow
- **Error Debugging** - Diagnose BLE connection issues and ATT protocol errors

The framework wraps the `hubblenetwork ready` CLI commands with comprehensive documentation, test workflows, and validation patterns.

## Installation

### Option 1: Plugin Marketplace (Recommended)

Install the entire pyhubblenetwork plugin from the Claude Code marketplace:

1. In Claude Code, use the command: `/install pyhubblenetwork`
2. Or install from GitHub: `/install github:HubbleNetwork/pyhubblenetwork`

The `hubble-ready-test` skill will be available along with other pyhubblenetwork skills.

### Option 2: Project-Level (Team/Local Development)

Copy this directory to your project's `.claude/skills/` directory:

```bash
# From the pyhubblenetwork repository root
cp -r skills/hubble-ready-test /path/to/your/project/.claude/skills/
```

The skill will be automatically available to all team members working on the project.

### Option 3: User-Level (Personal Use)

Copy to your user-level Claude skills directory:

```bash
# Copy to user skills directory
cp -r skills/hubble-ready-test ~/.claude/skills/
```

The skill will be available across all your projects.

## Usage

### Invoke the Testing Framework

In Claude Code, use the skill name with a forward slash:

```
/hubble-ready-test
```

This loads the testing framework and provides Claude with comprehensive test command documentation.

### Example Testing Workflows

**Test 1: Device Discovery**
```
Use the hubble-ready-test skill to scan for devices and validate they're readable
```

**Test 2: Validate Encryption Key Write**
```
Use hubble-ready-test to read encryption mode, write a key, and verify it succeeded
```

**Test 3: Full Provisioning Test**
```
Use hubble-ready-test to provision a device and verify all steps completed successfully
```

## What's Included

### SKILL.md (Primary Documentation)

Comprehensive testing framework documentation with:

- **Test Prerequisites** - BLE adapter requirements and permissions
- **10 Test Commands** - Complete reference for all `hubblenetwork ready` commands
- **Test Workflows** - Step-by-step validation patterns
- **Error Debugging** - ATT protocol errors, connection issues, and solutions
- **Best Practices** - JSON output, timeout recommendations, verification patterns

### Example Outputs (examples/ directory)

Sample JSON responses for common test scenarios:

- `scan-output.json` - Successful device discovery
- `read-status-output.json` - Device status read
- `provision-output.json` - Complete provisioning flow
- `error-connection-failed.json` - Connection timeout error
- `error-invalid-key.json` - Invalid key size error with ATT code

These examples help Claude understand response structures without running commands.

## Test Command Categories

### Discovery Tests
- `scan` - Find Hubble Ready devices (0xFCA7 service)
- `info` - Read all characteristics from a device

### Read Validation Tests
- `read-status` - Firmware version and provisioning flags
- `read-key-info` - Encryption mode (AES-128/256-CTR)
- `read-config` - EID configuration
- `read-time` - Device Unix timestamp

### Write Validation Tests
- `write-key` - Write encryption key (16 or 32 bytes)
- `write-config` - Write EID configuration
- `write-time` - Synchronize device time

### Integration Test
- `provision` - Complete workflow: scan → register → write key/config/time

## Requirements

- **Python SDK**: `pyhubblenetwork` installed
- **BLE Adapter**: Built-in or USB Bluetooth adapter
- **Permissions**: BLE access (varies by OS)
- **Environment Variables** (for provisioning): `HUBBLE_ORG_ID`, `HUBBLE_API_TOKEN`

## Key Features

### JSON-Based Testing

All commands support `--format json` for structured test results:

```bash
hubblenetwork ready scan --format json
```

Enables automated validation, error detail extraction, and timing analysis.

### Comprehensive Error Handling

Framework documents all common test failures:

- BLE adapter issues
- Permission problems
- Connection timeouts
- ATT protocol errors (with error codes)
- Invalid key sizes
- Device not found errors

### Test Validation Patterns

Pre-defined workflows for:

- Device discovery validation
- Encryption key write testing
- Configuration update verification
- Time synchronization testing
- Full provisioning integration tests

### Debugging Guidance

Step-by-step debugging instructions for:

- Connection failures
- ATT error codes (0x0D, 0x0E, etc.)
- Permission issues
- Invalid parameters
- Device selection problems

## Testing Best Practices

The framework emphasizes:

1. **Always use JSON format** - Structured output for automation
2. **Read before write** - Understand current state first
3. **Verify writes** - Read back to confirm changes
4. **Set appropriate timeouts** - Adjust based on signal strength
5. **Check status flags** - Determine provisioning state
6. **Capture test results** - Enable programmatic validation

## File Structure

```
skills/hubble-ready-test/        # For plugin marketplace distribution
├── SKILL.md                     # Primary skill documentation (~1000 lines)
├── README.md                    # This file
└── examples/
    ├── scan-output.json
    ├── read-status-output.json
    ├── provision-output.json
    ├── error-connection-failed.json
    └── error-invalid-key.json

.claude/skills/hubble-ready-test/  # For local project development
└── (same structure)
```

## Source Code References

For implementation details:

- CLI: `src/hubblenetwork/cli.py` (lines 852-2136)
- BLE Module: `src/hubblenetwork/ready.py`
- Error Codes: `src/hubblenetwork/errors.py`

## Support

For testing framework questions:

1. Review SKILL.md for detailed command documentation
2. Check examples/ for sample test outputs
3. See debugging section for common issues
4. Review source code for implementation details

## Version

This testing framework wraps the `hubblenetwork ready` commands. It automatically stays synchronized with CLI changes since it documents exact command syntax.

## License

Same as pyhubblenetwork SDK.
