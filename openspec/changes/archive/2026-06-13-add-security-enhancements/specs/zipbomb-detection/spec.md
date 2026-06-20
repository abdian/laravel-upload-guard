# Zip Bomb Detection

## ADDED Requirements

### Requirement: Compression Ratio Analysis

The system SHALL analyze the compression ratio of archive files to detect potential zip bombs (decompression bombs).

#### Scenario: Extreme compression ratio is detected
- **WHEN** an archive has a compressed-to-uncompressed ratio greater than 100:1
- **AND** zip bomb detection is enabled
- **THEN** the scanner SHALL reject with "Potential zip bomb: compression ratio exceeds threshold"

#### Scenario: Configurable ratio threshold
- **WHEN** administrator sets `max_compression_ratio` to 50
- **THEN** archives with ratio > 50:1 SHALL be rejected

#### Scenario: Normal compression is allowed
- **WHEN** an archive has a compression ratio of 10:1 or less
- **THEN** the scanner SHALL allow the archive

#### Scenario: Ratio calculated before extraction
- **WHEN** analyzing an archive
- **THEN** the system SHALL calculate ratio using archive metadata
- **AND** SHALL NOT extract files to calculate size

### Requirement: Uncompressed Size Limit

The system SHALL enforce a maximum total uncompressed size to prevent resource exhaustion.

#### Scenario: Uncompressed size exceeds limit
- **WHEN** the total uncompressed size of archive contents exceeds 500MB (default)
- **THEN** the scanner SHALL reject with "Archive uncompressed size exceeds limit"

#### Scenario: Configurable size limit
- **WHEN** administrator sets `max_uncompressed_size` to 100MB
- **THEN** archives exceeding 100MB uncompressed SHALL be rejected

#### Scenario: Size calculated incrementally
- **WHEN** scanning archive metadata
- **THEN** the system SHALL sum uncompressed sizes
- **AND** SHALL exit early when limit is exceeded

#### Scenario: Multiple small files summed
- **WHEN** an archive contains 1000 files of 1MB each (1GB total)
- **AND** limit is 500MB
- **THEN** the scanner SHALL reject the archive

### Requirement: File Count Limit

The system SHALL enforce a maximum number of files in an archive to prevent resource exhaustion during scanning.

#### Scenario: File count exceeds limit
- **WHEN** an archive contains more than 10000 files (default)
- **THEN** the scanner SHALL reject with "Archive contains too many files"

#### Scenario: Configurable file limit
- **WHEN** administrator sets `max_files_count` to 1000
- **THEN** archives with more than 1000 files SHALL be rejected

#### Scenario: Nested files counted
- **WHEN** an archive contains nested archives
- **THEN** files in nested archives SHALL be counted toward the limit

#### Scenario: Count checked early
- **WHEN** scanning archive metadata
- **THEN** the system SHALL check file count before processing contents

### Requirement: Recursive Bomb Detection

The system SHALL detect recursive/nested zip bombs where archives contain archives that contain archives, etc.

#### Scenario: Nested archives within limit
- **WHEN** an archive contains nested archives
- **AND** total nesting depth is 3 or less (default)
- **THEN** the scanner SHALL scan all levels

#### Scenario: Excessive nesting rejected
- **WHEN** archive nesting exceeds the configured depth limit
- **THEN** the scanner SHALL reject with "Archive nesting depth exceeds limit"

#### Scenario: Configurable nesting depth
- **WHEN** administrator sets `max_nesting_depth` to 2
- **THEN** archives with 3+ levels of nesting SHALL be rejected

#### Scenario: Self-referencing archive detected
- **WHEN** an archive appears to contain itself (infinite recursion pattern)
- **THEN** the scanner SHALL detect and reject it

### Requirement: Quine Detection

The system SHALL detect quine-style zip bombs where the archive contains a copy of itself.

#### Scenario: Archive contains itself
- **WHEN** an archive's contents include a file identical to the archive itself
- **THEN** the scanner SHALL reject with "Self-referencing archive detected"

#### Scenario: Similar size detection
- **WHEN** an archive contains a file with the same size and similar name
- **THEN** the scanner SHALL flag it for additional scrutiny

### Requirement: Early Termination

The system SHALL terminate scanning as soon as any bomb indicator is detected to prevent resource exhaustion.

#### Scenario: Exit on first ratio violation
- **WHEN** cumulative uncompressed size indicates ratio will exceed limit
- **THEN** the scanner SHALL stop scanning immediately

#### Scenario: Exit on file count violation
- **WHEN** file count reaches the configured limit during scanning
- **THEN** the scanner SHALL stop and reject

#### Scenario: Memory-bounded scanning
- **WHEN** scanning archive metadata
- **THEN** the system SHALL NOT load full file contents into memory
- **AND** SHALL use streaming/incremental processing

#### Scenario: Timeout protection
- **WHEN** archive scanning takes longer than the configured timeout
- **THEN** the system SHALL terminate and reject with "Archive scanning timeout"
