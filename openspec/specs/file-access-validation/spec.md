# file-access-validation Specification

## Purpose
TBD - created by archiving change prepare-production-release. Update Purpose after archive.
## Requirements
### Requirement: Correct Path Confinement

The system SHALL confine validated files to allowed directories using a boundary-correct prefix comparison, SHALL fail closed on an empty allow-list, and SHALL reject null-byte paths before resolving them.

#### Scenario: Sibling-prefix directory is rejected
- **WHEN** the allow-list contains `/storage/app` and a file resolves to `/storage/app-evil/x`
- **THEN** validation SHALL reject it (the comparison SHALL require a trailing directory separator)

#### Scenario: Empty allow-list fails closed
- **WHEN** the configured allow-list resolves to empty in a Laravel context
- **THEN** validation SHALL reject rather than allow all paths

#### Scenario: Null-byte path is handled safely
- **WHEN** a path contains a null byte
- **THEN** validation SHALL detect and reject it before calling `realpath()`, without throwing an uncaught error

#### Scenario: Upload temp dir is included by default
- **WHEN** no explicit allow-list is configured
- **THEN** the defaults SHALL include `upload_tmp_dir` in addition to the system temp and storage paths

### Requirement: Honest TOCTOU Scope and Destination Validation

The system SHALL provide a helper to validate an attacker-chosen destination path immediately before a move/store operation, and the documentation SHALL state that scanning the PHP temp file does not by itself close the temp-to-storage time-of-check/time-of-use window.

#### Scenario: Destination path is validated before move
- **WHEN** an application moves a validated upload to a destination derived from user input
- **THEN** the destination-validation helper SHALL reject traversal/symlink destinations before the move

