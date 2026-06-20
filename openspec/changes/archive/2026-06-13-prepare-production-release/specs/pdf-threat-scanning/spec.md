# PDF Threat Scanning

## ADDED Requirements

### Requirement: Decode Before Scanning

The system SHALL inflate PDF stream filters (`FlateDecode`, `LZWDecode`, `ASCII85Decode`, `ASCIIHexDecode`), parse object streams (`/ObjStm`), and decode `#xx` name escapes before matching for dangerous content.

#### Scenario: JavaScript inside a compressed stream is detected
- **WHEN** a PDF stores `/JavaScript` / `/JS` inside a `FlateDecode` stream or `/ObjStm`
- **THEN** the scanner SHALL inflate the stream and detect the JavaScript

#### Scenario: Hex-escaped names are decoded
- **WHEN** a PDF uses `/J#61vaScript` or similarly hex-escaped names
- **THEN** the scanner SHALL decode the name and detect it as `/JavaScript`

### Requirement: Auto-Run and Action Coverage with Anchored Matching

The system SHALL detect auto-run triggers `/OpenAction` and `/AA` in addition to existing actions, SHALL resolve indirect references, and SHALL anchor name/action matches on PDF delimiters to avoid false positives.

#### Scenario: OpenAction launching JavaScript is detected
- **WHEN** a PDF defines an `/OpenAction` (directly or via indirect reference) that runs JavaScript or `/Launch`
- **THEN** the scanner SHALL flag it

#### Scenario: Incidental substrings do not trigger false positives
- **WHEN** a PDF contains a `/Producer` value like `https://javascript.info` or names like `/Sounds` or `/Movies`
- **THEN** the scanner SHALL NOT flag these as `/JavaScript`, `/Sound`, or `/Movie`

### Requirement: Encrypted PDF Handling

The system SHALL handle encrypted PDFs explicitly rather than passing them unscanned, and SHALL remove the `count > 1` `/Encrypt` heuristic.

#### Scenario: Single-Encrypt PDF is not silently passed
- **WHEN** a PDF contains exactly one `/Encrypt` dictionary
- **THEN** the scanner SHALL decrypt it with the empty/owner password and scan the cleartext, or quarantine/reject it where decryption is not possible
- **AND** SHALL NOT pass it as safe merely because there is only one `/Encrypt`

### Requirement: Accurate Page Counting

The system SHALL determine PDF page count from the catalog page tree `/Count` (after inflating object streams), SHALL NOT hard-fail availability checks on an indeterminate count, and SHALL apply the same access guards as the PDF scanner.

#### Scenario: Compressed PDF page count is correct
- **WHEN** a valid PDF stores its page tree inside object streams (default output of common tools)
- **THEN** page counting SHALL return the true count
- **AND** SHALL NOT report 0 and reject the file

#### Scenario: Injected page tokens do not inflate the count
- **WHEN** a 1-page PDF has many fake `/Type /Page` tokens injected into its bytes
- **THEN** page counting SHALL report the authoritative count, not the injected token count

#### Scenario: Indeterminate count does not break uploads
- **WHEN** the page count genuinely cannot be determined
- **THEN** the min/max page check SHALL be skipped and logged rather than hard-failing the upload
