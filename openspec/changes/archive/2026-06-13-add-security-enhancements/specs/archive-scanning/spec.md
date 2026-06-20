# Archive Content Scanning

## ADDED Requirements

### Requirement: Archive Content Scanning

The system SHALL scan the contents of archive files (ZIP, RAR, TAR, 7Z, GZIP) to detect malicious files, dangerous extensions, and path traversal attacks without extracting files to disk.

#### Scenario: ZIP file with PHP backdoor is rejected
- **WHEN** a ZIP archive contains a file with `.php` extension
- **AND** archive scanning is enabled
- **THEN** the scanner SHALL reject the archive
- **AND** report "Dangerous file detected in archive: filename.php"

#### Scenario: Archive with executable is rejected
- **WHEN** an archive contains files with extensions `.exe`, `.bat`, `.sh`, `.cmd`, `.ps1`, `.phar`
- **THEN** the scanner SHALL reject the archive
- **AND** list all dangerous files found

#### Scenario: Clean archive passes validation
- **WHEN** an archive contains only allowed file types (e.g., images, documents)
- **AND** no path traversal patterns exist
- **THEN** the scanner SHALL allow the archive

#### Scenario: Configurable blocked extensions
- **WHEN** the administrator configures custom blocked extensions
- **THEN** the scanner SHALL use the configured list
- **AND** merge with default blocked extensions

### Requirement: Path Traversal Detection

The system SHALL detect and block archives containing path traversal sequences that could write files outside the intended directory.

#### Scenario: Archive with path traversal is rejected
- **WHEN** an archive contains a file path like `../../../etc/passwd`
- **THEN** the scanner SHALL reject the archive
- **AND** report "Path traversal detected: ../../../etc/passwd"

#### Scenario: Archive with Windows path traversal is rejected
- **WHEN** an archive contains a file path like `..\..\..\windows\system32\config`
- **THEN** the scanner SHALL reject the archive

#### Scenario: Archive with absolute path is rejected
- **WHEN** an archive contains an absolute path like `/etc/passwd` or `C:\Windows\System32`
- **THEN** the scanner SHALL reject the archive
- **AND** report "Absolute path detected in archive"

#### Scenario: Encoded path traversal is detected
- **WHEN** an archive contains URL-encoded traversal like `%2e%2e%2f`
- **THEN** the scanner SHALL detect and reject it

### Requirement: Zip Bomb Detection

The system SHALL detect and block zip bombs (decompression bombs) that could cause denial of service through resource exhaustion.

#### Scenario: High compression ratio archive is rejected
- **WHEN** an archive has a compression ratio exceeding the configured threshold (default: 100:1)
- **THEN** the scanner SHALL reject the archive
- **AND** report "Potential zip bomb detected: compression ratio X:1"

#### Scenario: Oversized uncompressed content is rejected
- **WHEN** the total uncompressed size exceeds the configured limit (default: 500MB)
- **THEN** the scanner SHALL reject the archive
- **AND** report "Archive uncompressed size exceeds limit"

#### Scenario: Excessive file count is rejected
- **WHEN** an archive contains more files than the configured limit (default: 10000)
- **THEN** the scanner SHALL reject the archive
- **AND** report "Archive contains too many files"

#### Scenario: Normal archive passes ratio check
- **WHEN** an archive has a reasonable compression ratio (e.g., 10:1)
- **AND** uncompressed size is within limits
- **THEN** the scanner SHALL allow the archive

### Requirement: Nested Archive Scanning

The system SHALL scan nested archives (archives within archives) up to a configurable depth limit.

#### Scenario: Nested archive is scanned
- **WHEN** a ZIP file contains another ZIP file
- **AND** nesting depth is within the configured limit (default: 3)
- **THEN** the scanner SHALL scan the nested archive for threats

#### Scenario: Deeply nested archive is rejected
- **WHEN** archive nesting exceeds the configured depth limit
- **THEN** the scanner SHALL reject the archive
- **AND** report "Archive nesting depth exceeds limit"

#### Scenario: Nested archive with threat is rejected
- **WHEN** a nested archive contains a dangerous file
- **THEN** the scanner SHALL reject the entire archive
- **AND** report the full path including nesting (e.g., "outer.zip/inner.zip/malware.php")

### Requirement: Archive Format Support

The system SHALL support multiple archive formats with graceful degradation for formats requiring optional extensions.

#### Scenario: ZIP files are supported natively
- **WHEN** a ZIP file is uploaded
- **THEN** the scanner SHALL scan it using PHP's ZipArchive

#### Scenario: TAR/GZIP files are supported natively
- **WHEN** a TAR or GZIP file is uploaded
- **THEN** the scanner SHALL scan it using PHP's PharData

#### Scenario: RAR files require optional extension
- **WHEN** a RAR file is uploaded
- **AND** the RAR extension is not installed
- **THEN** the scanner SHALL reject with "RAR scanning requires rar extension"
- **OR** allow based on configuration (fail-open vs fail-closed)

#### Scenario: Unsupported format handling
- **WHEN** an archive format is not supported
- **THEN** the scanner SHALL reject with "Unsupported archive format"

### Requirement: SafeguardArchive Validation Rule

The system SHALL provide a `safeguard_archive` validation rule for Laravel form validation.

#### Scenario: Rule used in validation
- **WHEN** a developer uses `'file' => 'required|safeguard_archive'`
- **THEN** the uploaded archive SHALL be scanned for all threats

#### Scenario: Rule with custom extensions
- **WHEN** a developer uses `'file' => 'safeguard_archive:allow_exe,allow_php'`
- **THEN** the specified extensions SHALL be allowed in the archive

#### Scenario: Fluent API usage
- **WHEN** a developer uses `(new Safeguard())->scanArchives()`
- **THEN** archive scanning SHALL be enabled for the validation
