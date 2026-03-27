# Release Notes

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
