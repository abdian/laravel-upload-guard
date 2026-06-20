# Security Logging

## ADDED Requirements

### Requirement: Centralized, Crash-Safe Logging

The system SHALL route all threat events through the centralized `SecurityLogger`, honoring the `logging.enabled`, `channel`, `detailed`, and `hash_algorithm` settings, and logging SHALL never break a request: hashing SHALL be guarded, the channel SHALL be validated with a fallback, and the log body SHALL be wrapped so a logging failure cannot propagate.

#### Scenario: Unresolved path does not crash logging
- **WHEN** a flagged file's real path cannot be resolved
- **THEN** the event SHALL still be logged without a hash and without throwing a `ValueError`

#### Scenario: Misconfigured channel does not break validation
- **WHEN** the configured log channel is undefined or invalid
- **THEN** logging SHALL fall back safely and validation SHALL continue

#### Scenario: All scanners log uniformly
- **WHEN** any scanner (PHP, SVG, image, MIME, PDF, archive, office) flags a threat
- **THEN** the event SHALL be recorded via `SecurityLogger` honoring the documented logging configuration

### Requirement: Injection-Safe Log Context

The system SHALL sanitize attacker-controlled strings (filenames, document metadata) before logging by stripping control characters and capping length, to prevent log injection and excessive output.

#### Scenario: CRLF in filename is sanitized
- **WHEN** an uploaded filename contains CR/LF or ANSI control sequences
- **THEN** the logged value SHALL have those characters stripped/escaped and be length-capped

### Requirement: Optional Quarantine of Rejected Files

The system SHALL support an opt-in quarantine that, when enabled, preserves a rejected file and a sanitized metadata record for forensic analysis, SHALL default to disabled, and SHALL NOT let a quarantine failure break validation or cause fail-open.

#### Scenario: Quarantine is disabled by default
- **WHEN** `quarantine.enabled` is not set
- **THEN** no file copy SHALL occur and validation behavior SHALL be unchanged

#### Scenario: Enabled quarantine stores file and sanitized metadata
- **WHEN** quarantine is enabled and a file is rejected
- **THEN** the file SHALL be copied to the configured quarantine path with a metadata record whose attacker-controlled fields (e.g. original filename) are control-char-stripped and length-capped

#### Scenario: Quarantine failure does not break validation
- **WHEN** the quarantine write fails (e.g. an unwritable path)
- **THEN** validation SHALL still complete with the file rejected, without throwing and without failing open
