# SVG Sanitization

## ADDED Requirements

### Requirement: Allowlist-Based Sanitization

The system SHALL process uploaded SVG files through an allowlist sanitizer that removes disallowed elements, attributes, and URL schemes, and SHALL make the sanitized output the version that is stored. Detection-only handling that leaves the original file intact SHALL NOT be relied upon.

#### Scenario: Unquoted event handler is neutralized
- **WHEN** an SVG contains an unquoted event handler such as `<svg onload=alert(1)>` or `<rect onclick=alert(1)/>`
- **THEN** the sanitizer SHALL remove the handler (or the file SHALL be rejected)
- **AND** the stored SVG SHALL contain no executable handler

#### Scenario: Whitespace/encoding-obfuscated javascript URI is neutralized
- **WHEN** an SVG contains `<a href=" javascript:alert(1)">` (leading whitespace) or an entity/URL-encoded `javascript:` scheme
- **THEN** the sanitizer SHALL strip the dangerous scheme (or reject the file)

### Requirement: XXE / DTD Elimination

The system SHALL reject or strip any DOCTYPE, DTD, or entity declaration in an uploaded SVG, and any XML parsing the package performs SHALL disable external-entity loading.

#### Scenario: External DTD without an internal subset is blocked
- **WHEN** an SVG contains `<!DOCTYPE svg SYSTEM "file:///etc/passwd">` or a `PUBLIC` external DTD with no internal subset
- **THEN** the file SHALL be rejected (or the DOCTYPE stripped)
- **AND** no external file or URL SHALL be fetched

#### Scenario: External entity loading is disabled during parsing
- **WHEN** the package parses SVG/XML internally
- **THEN** it SHALL install a denying external-entity loader and parse with `LIBXML_NONET` and without entity substitution
- **AND** on PHP < 8 it SHALL additionally call `libxml_disable_entity_loader(true)`

### Requirement: Case/Encoding Robustness Without Over-Rejection

The system SHALL handle SVG content case-insensitively and decode entity/URL encodings when evaluating safety, while allowing benign standard SVG elements permitted by the configured allowlist.

#### Scenario: Benign SVG is preserved
- **WHEN** an SVG uses only allowlisted elements and attributes with no scripts, handlers, foreign content, or DTD
- **THEN** the sanitizer SHALL pass it and preserve its visual meaning
