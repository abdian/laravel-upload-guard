# Office Document Scanning

## ADDED Requirements

### Requirement: Legacy OLE and OOXML Coverage

The system SHALL detect macros, OLE objects, and ActiveX controls in both Office Open XML (ZIP) documents and legacy OLE/CFB documents (`.doc`/`.xls`/`.ppt`), and SHALL fail closed when macro blocking is enabled and a container cannot be fully parsed.

#### Scenario: Legacy macro document is blocked
- **WHEN** a legacy OLE/CFB `.doc` (magic `D0CF11E0`) contains an `Auto_Open` VBA macro
- **THEN** the scanner SHALL detect the macro and the file SHALL be rejected
- **AND** SHALL NOT pass merely because the file is not an OOXML ZIP

#### Scenario: Unparsable container fails closed
- **WHEN** macro blocking is enabled and a document container cannot be fully parsed
- **THEN** the file SHALL be rejected rather than passed

### Requirement: Case-Insensitive OPC and Relationship-Based Resolution

The system SHALL look up Office package parts case-insensitively and SHALL resolve VBA/OLE/ActiveX content via OPC relationships and `[Content_Types].xml` rather than relying on exact filename patterns.

#### Scenario: Lowercase content-types part is still scanned
- **WHEN** a `.docx` stores its content-types part as `[content_types].xml` (lowercase) which Office still opens
- **THEN** the scanner SHALL locate it case-insensitively and scan the document

#### Scenario: Renamed VBA storage is detected
- **WHEN** the VBA project is stored under a non-standard or renamed part
- **THEN** the scanner SHALL detect it via relationships/content-types

### Requirement: Configuration Integrity

The system SHALL NOT let configuration loading overwrite explicitly-set fluent flags, so caller intent is preserved.

#### Scenario: Explicit allowMacros is honored
- **WHEN** a caller sets `allowMacros()` on the rule
- **THEN** loading configuration SHALL NOT silently re-enable macro blocking
