# Symlink/Hardlink Validation

## ADDED Requirements

### Requirement: Symlink Detection

The system SHALL detect and reject symbolic links to prevent TOCTOU (time-of-check-time-of-use) attacks where an attacker replaces a file with a symlink between validation and processing.

#### Scenario: Symlink to system file is rejected
- **WHEN** an uploaded file is a symbolic link
- **AND** the link points to a system file (e.g., `/etc/passwd`)
- **THEN** the scanner SHALL reject with "Symbolic link detected"
- **AND** SHALL NOT read the linked file contents

#### Scenario: Symlink to file outside upload directory is rejected
- **WHEN** an uploaded file is a symbolic link
- **AND** the target is outside the allowed upload directories
- **THEN** the scanner SHALL reject the file

#### Scenario: Regular file is processed normally
- **WHEN** an uploaded file is a regular file (not a symlink)
- **THEN** the scanner SHALL process it normally

#### Scenario: Symlink detection uses is_link()
- **WHEN** validating a file path
- **THEN** the system SHALL use PHP's `is_link()` function
- **AND** check BEFORE reading any file contents

### Requirement: Path Validation

The system SHALL validate that file paths resolve to allowed directories to prevent directory traversal attacks.

#### Scenario: File in temp directory is allowed
- **WHEN** a file's real path is within `sys_get_temp_dir()`
- **THEN** the scanner SHALL allow processing

#### Scenario: File in Laravel storage is allowed
- **WHEN** a file's real path is within `storage_path('app')`
- **THEN** the scanner SHALL allow processing

#### Scenario: File outside allowed paths is rejected
- **WHEN** a file's real path resolves outside all allowed directories
- **THEN** the scanner SHALL reject with "File path outside allowed directories"

#### Scenario: Path with traversal is resolved
- **WHEN** a file path contains `../` sequences
- **THEN** the system SHALL use `realpath()` to resolve the actual location
- **AND** validate the resolved path

#### Scenario: Configurable allowed paths
- **WHEN** administrator configures custom allowed paths
- **THEN** the system SHALL use the configured paths
- **AND** merge with default allowed paths

### Requirement: Real Path Resolution

The system SHALL resolve and validate the real path of files before processing to prevent path manipulation attacks.

#### Scenario: realpath() returns false
- **WHEN** `realpath()` returns false for a file
- **THEN** the scanner SHALL reject with "Unable to resolve file path"

#### Scenario: Path resolution before file operations
- **WHEN** any file operation is performed
- **THEN** the system SHALL first resolve the real path
- **AND** validate it is within allowed directories

#### Scenario: Null byte injection is blocked
- **WHEN** a file path contains null bytes
- **THEN** the system SHALL reject the path

### Requirement: Scanner Integration

All scanner classes SHALL validate file access before performing any file operations.

#### Scenario: SvgScanner validates file access
- **WHEN** `SvgScanner::scan()` is called
- **THEN** it SHALL validate file access before reading content

#### Scenario: ImageScanner validates file access
- **WHEN** `ImageScanner::scan()` is called
- **THEN** it SHALL validate file access before processing

#### Scenario: PdfScanner validates file access
- **WHEN** `PdfScanner::scan()` is called
- **THEN** it SHALL validate file access before reading

#### Scenario: PhpCodeScanner validates file access
- **WHEN** `PhpCodeScanner::scan()` is called
- **THEN** it SHALL validate file access before scanning

#### Scenario: New scanners inherit validation
- **WHEN** new scanner classes are created (ArchiveScanner, OfficeScanner)
- **THEN** they SHALL use the same validation trait

### Requirement: ValidatesFileAccess Trait

The system SHALL provide a reusable trait for file access validation that all scanners can use.

#### Scenario: Trait provides validateFileAccess method
- **WHEN** a scanner uses the `ValidatesFileAccess` trait
- **THEN** it SHALL have access to `validateFileAccess(string $path): bool`

#### Scenario: Validation returns false for symlinks
- **WHEN** `validateFileAccess()` is called with a symlink path
- **THEN** it SHALL return `false`

#### Scenario: Validation returns false for paths outside allowed dirs
- **WHEN** `validateFileAccess()` is called with a path outside allowed directories
- **THEN** it SHALL return `false`

#### Scenario: Validation returns true for valid paths
- **WHEN** `validateFileAccess()` is called with a regular file in allowed directory
- **THEN** it SHALL return `true`
