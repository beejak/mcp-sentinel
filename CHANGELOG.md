# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.0-beta.4] - 2026-01-24

### Added
- **Advanced Logging System**:
  - Structured JSON logging support for file output.
  - Console logging with `rich` formatting and colors.
  - Log rotation (10MB max size, 5 backups).
  - CLI options `--log-level` and `--log-file`.
- **Enhanced CLI**:
  - Interactive prompts using `questionary` when required arguments are missing.
  - Improved help messages and command structure.
- **Documentation**:
  - Added `TUTORIAL.md` covering CLI and logging features.

### Changed
- Refactored `main.py` to use `setup_logging` before command execution.
- Updated `ScanResult` model to use string status instead of enum for better compatibility.

### Fixed
- Fixed `ScanStatus` import error in tests.
- Improved test coverage for CLI and logging modules.

## [v1.0.0-beta.3] - 2026-01-15

### Added
- Phase 4.3 AI Analysis Engine integration.
- Support for Claude 3.5 Sonnet.
- Cost tracking and budget management.

## [v1.0.0-beta.2] - 2026-01-10

### Added
- Phase 4.2.2 Semantic Analysis improvements.
- JavaScript multi-line comment detection.
- Python fixture detection enhancements.
