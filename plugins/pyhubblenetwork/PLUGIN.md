# pyhubblenetwork Claude Code Plugin

Python SDK and CLI for communicating with Hubble Network IoT devices over Bluetooth Low Energy (BLE).

## Plugin Overview

This plugin provides skills for testing and provisioning Hubble Network devices:

- **hubble-ready-test** - Comprehensive testing framework for Hubble Ready devices over BLE

## Installation

Install this plugin from the Claude Code marketplace:

```
/install pyhubblenetwork
```

Or install directly from GitHub:

```
/install github:HubbleNetwork/pyhubblenetwork
```

## Requirements

To use the skills in this plugin, you need:

1. **Python SDK**: Install the pyhubblenetwork package
   ```bash
   pip install pyhubblenetwork
   ```

2. **BLE Adapter**: Built-in or USB Bluetooth adapter
   - macOS: CoreBluetooth (requires GUI session)
   - Linux: BlueZ stack (user must be in `bluetooth` group)
   - Windows: Compatible BLE stack

3. **Permissions**: Bluetooth access permissions for your OS

4. **Environment Variables** (for provisioning):
   ```bash
   export HUBBLE_ORG_ID="your-org-id"
   export HUBBLE_API_TOKEN="your-api-token"
   ```

## Skills

### hubble-ready-test

Comprehensive testing framework for Hubble Ready devices.

**Use when:**
- Testing Hubble Ready device functionality
- Validating BLE connectivity
- Verifying device characteristics
- Testing encryption key writes
- Validating configuration updates
- Debugging provisioning workflows

**Invoke:**
```
/hubble-ready-test
```

**Features:**
- 10 test commands (scan, info, read/write characteristics, provision)
- 5 pre-defined test workflows
- JSON-based test output
- Comprehensive error handling and debugging guidance
- ATT protocol error code reference
- BLE troubleshooting documentation

**Example Usage:**
```
Use the hubble-ready-test skill to scan for devices and validate they're readable
```

## Documentation

- **SDK Documentation**: See [README.md](README.md)
- **Development Guide**: See [CLAUDE.md](CLAUDE.md)
- **Skill Documentation**: See [skills/hubble-ready-test/README.md](skills/hubble-ready-test/README.md)

## Support

- **GitHub**: [HubbleNetwork/pyhubblenetwork](https://github.com/HubbleNetwork/pyhubblenetwork)
- **Issues**: Report issues on GitHub

## License

See [LICENSE](LICENSE) file for details.
