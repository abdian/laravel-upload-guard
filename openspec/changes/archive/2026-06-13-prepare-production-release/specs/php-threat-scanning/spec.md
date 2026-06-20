# PHP / Script Code Scanning

## ADDED Requirements

### Requirement: Always Scan Raw Bytes for Code

The system SHALL scan the full content of every uploaded file for PHP/script openers regardless of its detected MIME type, and SHALL NOT skip scanning because a file is classified as binary (image, PDF, archive, or `application/octet-stream`).

#### Scenario: Polyglot web shell in a binary file is detected
- **WHEN** a file has a valid image/PDF/ZIP magic header and contains `<?php ... ?>` later in its bytes
- **THEN** the scanner SHALL flag the PHP code and the file SHALL be rejected
- **AND** this SHALL hold for `image/jpeg`, `image/png`, `image/gif`, `image/bmp`, `application/pdf`, `application/zip`, and `application/octet-stream`

#### Scenario: octet-stream is not an automatic pass
- **WHEN** a file of unknown type (`application/octet-stream` / `null`) contains a PHP opener
- **THEN** the scanner SHALL flag it
- **AND** SHALL NOT short-circuit to "safe"

### Requirement: Obfuscation-Resistant Opener Detection

The system SHALL flag every PHP/script opener unconditionally, including bare `<?` (except `<?xml`), `<?=`, `<script language=php>`, `<%`, and `__halt_compiler`.

#### Scenario: Short tags are flagged
- **WHEN** a non-allowed upload contains `<?=` or a bare `<?` (not `<?xml`)
- **THEN** the scanner SHALL flag a PHP opener

#### Scenario: Dynamic dispatch inside a PHP region is detected
- **WHEN** content within a PHP open-tag region invokes code via a variable function, `call_user_func`, concatenated function name, or the backtick operator
- **THEN** deep analysis (when enabled) SHALL flag it using tokenization rather than literal substring matching

### Requirement: Low False Positives Outside PHP Context

The system SHALL gate dangerous-function/keyword detection on the presence of an actual PHP open-tag region, so that legitimate non-PHP files are not rejected merely for containing words such as `eval`, `system`, or `exec`.

#### Scenario: Benign source files pass
- **WHEN** a `.js`, `.py`, `.md`, `.csv`, or `.sql` file contains words like `require()`, `os.system()`, or `eval()` outside any PHP open tag
- **THEN** the function/keyword layer SHALL NOT flag the file

### Requirement: Coherent Scan Modes

The system SHALL ensure the `strict` scan mode is a superset of `default`, and SHALL raise a configuration error or warning when `custom` mode is selected with an empty function list rather than silently scanning for nothing.

#### Scenario: strict mode does not lose coverage
- **WHEN** mode is `strict`
- **THEN** the scanned function set SHALL include everything in `default` (e.g. `include`/`require`, `base64_decode`, `move_uploaded_file`) at minimum

#### Scenario: empty custom list is reported
- **WHEN** mode is `custom` and `scan_functions` is empty
- **THEN** the system SHALL emit a configuration warning/error rather than disabling the function layer silently
