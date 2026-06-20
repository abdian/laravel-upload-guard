# Office Document Macro Detection

## ADDED Requirements

### Requirement: VBA Macro Detection

The system SHALL detect VBA macros in Office Open XML documents (DOCX, XLSX, PPTX) by inspecting the archive structure for macro indicators.

#### Scenario: Document with vbaProject.bin is detected
- **WHEN** an Office document contains a `vbaProject.bin` file in any directory
- **THEN** the scanner SHALL detect it as containing macros
- **AND** report "VBA macro detected: vbaProject.bin found"

#### Scenario: Macro in word subdirectory
- **WHEN** a DOCX file contains `word/vbaProject.bin`
- **THEN** the scanner SHALL detect the macro

#### Scenario: Macro in xl subdirectory
- **WHEN** an XLSX file contains `xl/vbaProject.bin`
- **THEN** the scanner SHALL detect the macro

#### Scenario: Document without macros passes
- **WHEN** an Office document contains no `vbaProject.bin`
- **AND** no macro content types are declared
- **THEN** the scanner SHALL allow the document

### Requirement: Content Types Macro Detection

The system SHALL parse the `[Content_Types].xml` file in Office documents to detect macro-enabled content types.

#### Scenario: Macro content type in DOCX
- **WHEN** `[Content_Types].xml` contains `application/vnd.ms-word.document.macroEnabled`
- **THEN** the scanner SHALL detect it as macro-enabled

#### Scenario: VBA project content type
- **WHEN** `[Content_Types].xml` contains `application/vnd.ms-office.vbaProject`
- **THEN** the scanner SHALL detect it as macro-enabled

#### Scenario: Excel macro content type
- **WHEN** `[Content_Types].xml` contains `application/vnd.ms-excel.sheet.macroEnabled.main+xml`
- **THEN** the scanner SHALL detect it as macro-enabled

#### Scenario: PowerPoint macro content type
- **WHEN** `[Content_Types].xml` contains `application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml`
- **THEN** the scanner SHALL detect it as macro-enabled

### Requirement: Extension Spoofing Detection

The system SHALL detect macro-enabled documents disguised with regular (non-macro) extensions.

#### Scenario: DOCM disguised as DOCX
- **WHEN** a file has `.docx` extension
- **AND** the file contains VBA macros
- **THEN** the scanner SHALL reject with "Macro-enabled document disguised as .docx"

#### Scenario: XLSM disguised as XLSX
- **WHEN** a file has `.xlsx` extension
- **AND** the file contains VBA macros
- **THEN** the scanner SHALL reject with "Macro-enabled document disguised as .xlsx"

#### Scenario: PPTM disguised as PPTX
- **WHEN** a file has `.pptx` extension
- **AND** the file contains VBA macros
- **THEN** the scanner SHALL reject with "Macro-enabled document disguised as .pptx"

#### Scenario: Legitimate macro-enabled extension
- **WHEN** a file has `.docm`, `.xlsm`, or `.pptm` extension
- **AND** macro blocking is not enabled
- **THEN** the scanner SHALL allow the file (with warning if logging enabled)

### Requirement: ActiveX Control Detection

The system SHALL optionally detect ActiveX controls embedded in Office documents.

#### Scenario: ActiveX control detected
- **WHEN** an Office document contains `activeX/activeX1.xml` or similar
- **AND** ActiveX detection is enabled in configuration
- **THEN** the scanner SHALL report "ActiveX control detected"

#### Scenario: ActiveX binary detected
- **WHEN** an Office document contains `.bin` files in `activeX/` directory
- **THEN** the scanner SHALL report "ActiveX binary detected"

#### Scenario: ActiveX detection disabled
- **WHEN** ActiveX detection is disabled in configuration
- **THEN** the scanner SHALL not check for ActiveX controls

### Requirement: SafeguardOffice Validation Rule

The system SHALL provide a `safeguard_office` validation rule for Laravel form validation.

#### Scenario: Rule blocks macros by default
- **WHEN** a developer uses `'file' => 'required|safeguard_office'`
- **AND** the file contains macros
- **THEN** validation SHALL fail with appropriate message

#### Scenario: Rule allows macros when configured
- **WHEN** a developer uses `'file' => 'safeguard_office:allow_macros'`
- **THEN** macro-enabled documents SHALL be allowed

#### Scenario: Fluent API for macro blocking
- **WHEN** a developer uses `(new Safeguard())->blockMacros()`
- **THEN** macro detection SHALL be enabled

#### Scenario: Fluent API for documents only
- **WHEN** a developer uses `(new Safeguard())->documentsOnly()->blockMacros()`
- **THEN** only Office documents SHALL be allowed
- **AND** macros SHALL be blocked

### Requirement: Office Format Support

The system SHALL support all Office Open XML formats and legacy Office formats.

#### Scenario: Modern Office formats supported
- **WHEN** files with extensions `.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`, `.pptm` are uploaded
- **THEN** the scanner SHALL process them as Office Open XML

#### Scenario: Legacy Office formats warning
- **WHEN** files with extensions `.doc`, `.xls`, `.ppt` (legacy binary formats) are uploaded
- **AND** the scanner cannot determine macro presence
- **THEN** the scanner SHALL warn "Legacy Office format - cannot verify macro-free"

#### Scenario: Non-Office file rejected
- **WHEN** a file is not an Office document
- **AND** `safeguard_office` rule is used
- **THEN** validation SHALL fail with "File is not a valid Office document"
