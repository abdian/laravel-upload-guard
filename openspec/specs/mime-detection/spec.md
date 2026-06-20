# mime-detection Specification

## Purpose
TBD - created by archiving change prepare-production-release. Update Purpose after archive.
## Requirements
### Requirement: Content-Based Type Classification

The system SHALL determine a file's type from its actual byte structure, reading a configurable header window of at least 512 bytes (and more where a format requires it), and SHALL NOT rely on the filename, client-provided MIME type, or only the first 16 bytes for any security decision.

#### Scenario: Appended-data polyglot is classified by its real container
- **WHEN** a file begins with a valid container header (e.g. `%PDF-`, `\xFF\xD8\xFF`, `PK\x03\x04`) and has unrelated data appended after it
- **THEN** detection SHALL classify it by its real container type
- **AND** the orchestrator SHALL still subject it to code scanning (see `php-threat-scanning`)

#### Scenario: Short signature requires structural validation
- **WHEN** a file starts with a 2-byte signature such as `BM`
- **THEN** detection SHALL confirm the structure (e.g. BMP file size at offset 2 and DIB header size at offset 14) before classifying it as `image/bmp`
- **AND** SHALL NOT classify arbitrary `BM`-prefixed content as an image

### Requirement: Subtype Disambiguation

The system SHALL disambiguate container families into their specific subtypes so that legitimate files are not mislabeled.

#### Scenario: OLE compound documents are disambiguated
- **WHEN** a file has the OLE/CFB magic `D0CF11E0A1B11AE1`
- **THEN** detection SHALL distinguish `.doc`/`.xls`/`.ppt`/`.msg` by their internal storages
- **AND** a genuine `.xls` SHALL detect as `application/vnd.ms-excel` (not `application/msword`) so it passes strict extension matching

#### Scenario: ZIP families and Java archives are disambiguated
- **WHEN** a ZIP-structured file is an Office OOXML, JAR/APK, EPUB, or ODF document
- **THEN** detection SHALL return the specific subtype
- **AND** a JAR/APK SHALL detect as `application/java-archive` and be treated as a dangerous type

#### Scenario: ftyp and RIFF subtypes are disambiguated
- **WHEN** a file is an ISO-BMFF (`ftyp`) or RIFF container
- **THEN** detection SHALL resolve the brand/format (e.g. mp4/mov/m4a/heic/avif, webp/avi/wav) rather than defaulting to a single type

### Requirement: Fail-Closed on Unknown Types

The system SHALL return `null` when a type cannot be confidently determined, and callers SHALL treat `null` as untrusted — never as a safe binary that bypasses scanning.

#### Scenario: Unknown content is not auto-allowed
- **WHEN** detection cannot match a signature and `fileinfo` is unavailable or returns nothing
- **THEN** `detect()` SHALL return `null`
- **AND** the orchestrator SHALL still run code scanning and SHALL NOT pass the file as "binary safe"

### Requirement: Deterministic, Memoized Detection

The system SHALL compute a file's detection result once per validation and reuse it, and the signature table SHALL contain no duplicate keys that silently drop entries.

#### Scenario: Detection is computed once
- **WHEN** the all-in-one rule runs multiple sub-scanners on one file
- **THEN** the detected type SHALL be computed once and shared
- **AND** repeated detection of the same file SHALL return a consistent result

