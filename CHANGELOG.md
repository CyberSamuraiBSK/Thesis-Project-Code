# 📖 Changelog

All notable changes to this project will be documented in this file.

## [v2.0.0] - 25/06/2026

### Fixed
- Restructured timestamp tracking logic to prevent memory leaks.
- Eliminated TOCTOU race conditions by moving pod state tracking inside synchronized locks.
- Added safe worker wrappers to recover cleanly from kubectl orchestration failures.

### Improved
- Removed all usage of `copy.deepcopy()`.
- Replaced deep-copy operations with lightweight snapshot generation under `stats_out_lock`.
- Reduced lock duration and memory overhead during whitelist evaluation.

## [v1.1.0] - 05/06/2026

### Changed
- Refactored code structure for improved readability and maintainability.
- Expanded inline documentation and comments.

## [v1.0.0] - 10/04/2026

### Added
- Initial thesis implementation of the Trust Engine.
