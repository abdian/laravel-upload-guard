# Image Threat Scanning

## ADDED Requirements

### Requirement: Decompression-Bomb Guard Before Decode

The system SHALL read image dimensions and byte size from the header and reject images exceeding a configurable pixel-count or byte cap BEFORE performing any decode or metadata-strip operation.

#### Scenario: Oversize image is rejected before decode
- **WHEN** a small file declares enormous dimensions (e.g. a 45-byte PNG header claiming 50000×50000)
- **THEN** the scanner SHALL reject it based on the header
- **AND** SHALL NOT call any `imagecreatefrom*` decode that would allocate the full pixel buffer

### Requirement: Full Metadata and Byte Scanning

The system SHALL scan all EXIF/IFD sections and the `COMMENT` data for embedded code (not a small tag allowlist), SHALL run the full PHP byte-scanner over image content, and SHALL operate without `ext-exif` by skipping EXIF parsing while still scanning bytes.

#### Scenario: Code hidden in metadata is detected
- **WHEN** a PHP opener or shell command is placed in an EXIF tag such as `Make`/`Model` or in the `COMMENT` segment
- **THEN** the scanner SHALL detect it

#### Scenario: Missing ext-exif does not reject all images
- **WHEN** `ext-exif` is unavailable
- **THEN** the scanner SHALL skip EXIF parsing but still scan the image bytes
- **AND** SHALL NOT reject the image solely because the extension is missing

### Requirement: Structural Trailing-Data Detection and Safe Re-Encoding

The system SHALL detect trailing data structurally (without a fixed minimum-size threshold and robust to repeated end markers), SHALL offer an optional re-encoding mode that strips appended/segment payloads, and any metadata-strip operation SHALL support all advertised formats or fail loudly.

#### Scenario: Trailing payload is detected
- **WHEN** data is appended after the image's true end-of-image structure (including a single extra GIF trailer byte)
- **THEN** the scanner SHALL detect the trailing data

#### Scenario: Re-encoding removes payloads
- **WHEN** the optional re-encode mode is enabled
- **THEN** the image SHALL be re-encoded to a clean file that no longer contains the appended/segment payload
