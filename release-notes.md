# Release Notes

## [0.9.0] - 2026-04-22

### Added
- feat(org): add period_exponent for AES-EAX device registration
- feat(ble): skip failed decrypts by default, add unified packet columns
- feat: add AES-128-EAX encrypted device registration support

### Fixed
- fix(org): decode API payload bytes in retrieve_packets
- fix(cli): rename SEQ column to SALT for AES-EAX packet display
- fix(crypto): show pre-scale-factor counter in AES-EAX decryption
- fix(cli): handle mixed packet types in streaming table printer
- fix(cloud): fix device registration

## [0.8.0] - 2026-04-14

### Added
- feat: add AES-EAX encrypted packet support
- feat(ble): add unencrypted protocol support with auto-detection

## [0.7.0] - 2026-04-13

### Added
- feat(crypto): change counter_mode from bool to UNIX_TIME/DEVICE_UPTIME string
- feat(sat): add status messages and --debug flag to sat scan commands

### Fixed
- fix(crypto): fix EID pool size to 128 for counter mode

### Documentation
- docs: document fixed EID pool size and --counter-mode flag

## [0.6.3] - 2026-04-01

### Added
- feat(sat): add mock-scan command for testing without hardware

### Tests
- test(sat): add GitHub Action and integration tests for mock scanning

## [0.6.2] - 2026-03-31

### Fixed
- fix(sat): improve Docker error reporting, socket fallback, and payload field name

## [0.6.1] - 2026-03-27

### Maintenance
- chore(sat): update Docker image to sdr-docker

## [0.6.0] - 2026-03-27

### Added
- feat(cli): add metrics devices command for device metrics

### Documentation
- docs: update CLAUDE.md with release workflow and current CLI commands

### Maintenance
- ci: consolidate release workflow to 3 jobs and add lint step
- ci: upgrade actions to supported versions

## [0.5.0] - 2026-03-27

### Added
- feat(org): add Organization.delete_device method
- feat(cli): add org delete-device command with confirmation prompt
- feat(cli): add ble validate command with EID type detection

## [0.4.1] - 2026-03-25

### Fixed
- fix(cli): improve sat scan Ctrl+C responsiveness
- fix(cli): improve sat scan Docker error handling

### Documentation
- docs: add satellite scanning docs and drop mypy

## [0.4.0] - 2026-03-24

### Added
- feat(cli): add sat scan command for satellite packet reception via PlutoSDR
- feat(org): add EID rotation params to register_device

## [0.3.0] - 2026-02-27

### Added
- feat(crypto): add counter-based EID decryption support
- feat(cli): encode BLE packet payloads as base64 in all output formats
- feat(device): display key as base64 in Device __str__
- feat(cli): make packet payload format configurable across output commands

### Maintenance
- chore: add .worktrees to .gitignore

## [0.2.0] - 2026-02-02

### Added
- feat(skill): add hubble-ready-test Claude Code skill
- feat(ready): implement write commands
- feat(ready): implement read commands
- feat(ready): add result dataclasses for testing
- feat(cli): update ready command JSON output structure
