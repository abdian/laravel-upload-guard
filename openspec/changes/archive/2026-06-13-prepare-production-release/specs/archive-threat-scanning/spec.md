# Archive Threat Scanning

## ADDED Requirements

### Requirement: Real Decompression-Bomb Detection

The system SHALL detect compression bombs and enforce size limits by streaming each entry through a bounded reader and counting actual decompressed bytes against a hard global cap, and SHALL NOT base security decisions on declared (central-directory) sizes.

#### Scenario: Forged central-directory size is ignored
- **WHEN** an archive declares a tiny uncompressed size in its central directory but actually expands far beyond the cap
- **THEN** the scanner SHALL detect the real expansion via streaming and reject the archive
- **AND** SHALL flag the declared-vs-actual size mismatch

#### Scenario: Classic zip bomb is blocked
- **WHEN** a highly nested or highly compressed bomb (42.zip-class) is uploaded
- **THEN** streaming SHALL abort once the global byte cap is exceeded and the file SHALL be rejected with bounded memory use

### Requirement: Robust Path and Extension Checks

The system SHALL inspect every dotted segment of each entry name against the dangerous-extension blocklist, normalize entry names before extraction of the extension, detect path traversal in both separator styles and absolute paths, and reject symlink/hardlink entries.

#### Scenario: Multi-level double extension is blocked
- **WHEN** an entry is named `shell.php.safe.txt`
- **THEN** the scanner SHALL detect the `php` segment and reject the archive

#### Scenario: Normalization defeats evasion
- **WHEN** an entry name uses trailing whitespace/dots/control characters or an NTFS ADS form such as `evil.php:.jpg`
- **THEN** the scanner SHALL normalize the name and reject the dangerous extension

#### Scenario: Traversal and links are blocked
- **WHEN** an entry uses `..\` (backslash), `../` (forward slash), an absolute path, or is a symlink/hardlink entry
- **THEN** the scanner SHALL reject the archive

### Requirement: Complete Blocklist, Nested Recursion, and Format Handling

The system SHALL maintain a complete dangerous-extension blocklist, SHALL actually recurse nested archives within the configured depth cap, and SHALL reject detected-but-unsupported or encrypted archive formats rather than passing them unscanned.

#### Scenario: Server-side handler extensions are blocked
- **WHEN** an entry has an extension such as `.pht`, `.phtml`, `.shtml`, `.htaccess`, `.inc`, or `web.config`
- **THEN** the scanner SHALL reject the archive

#### Scenario: Nested archive is actually scanned
- **WHEN** an archive contains another archive within the depth cap
- **THEN** the scanner SHALL recurse into it and apply all checks, not merely flag its presence

#### Scenario: Unsupported/encrypted format is not silently passed
- **WHEN** a detected archive is an unsupported format (e.g. ISO/CAB) or is encrypted so its entries cannot be inspected
- **THEN** the scanner SHALL reject it rather than returning safe
