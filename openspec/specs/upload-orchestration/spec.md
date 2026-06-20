# upload-orchestration Specification

## Purpose
TBD - created by archiving change prepare-production-release. Update Purpose after archive.
## Requirements
### Requirement: Fail-Closed All-in-One Rule

The `safeguard` all-in-one rule SHALL enable archive and Office-macro scanning from configuration by default, SHALL route to type-specific scanners by content-derived type (using a case-insensitive extension only as a secondary signal), and SHALL fail closed when the detected type is `null` or a recognized container is not fully handled.

#### Scenario: Default rule blocks archive traversal
- **WHEN** `required|safeguard` validates a ZIP containing `../../../shell.php`
- **THEN** the file SHALL be rejected by default without requiring a fluent `scanArchives()` call

#### Scenario: Default rule blocks macro documents
- **WHEN** `required|safeguard` validates a `.docx` containing a VBA macro
- **THEN** the file SHALL be rejected by default

#### Scenario: Case-variant extension is still routed
- **WHEN** a malicious SVG is uploaded as `evil.SVG` (uppercase) and detected as `text/html`
- **THEN** the orchestrator SHALL still route it to SVG sanitization

#### Scenario: Unknown type fails closed
- **WHEN** the detected type is `null`
- **THEN** the orchestrator SHALL still run code scanning and SHALL NOT pass the file as safe binary

### Requirement: Single-Pass Performance Pipeline

The system SHALL read and decode each uploaded file once and share the result across sub-scanners, SHALL enforce a configurable maximum scan size with a defined over-cap policy, and SHALL avoid repeated full-file reads and unbounded passes.

#### Scenario: One read drives all scanners
- **WHEN** the all-in-one rule runs several sub-scanners on one file
- **THEN** the file content/handle SHALL be obtained once and reused rather than re-read per sub-scanner

#### Scenario: Oversize upload is bounded
- **WHEN** an upload exceeds the configured `max_scan_size`
- **THEN** the system SHALL apply the configured over-cap policy (reject or header-only) rather than scanning unbounded content

### Requirement: Config Coherence and Deterministic Error Semantics

Every documented configuration key SHALL affect behavior with fail-closed defaults, scanner access to `config()`/`logger()`/`request()` SHALL be guarded for non-HTTP contexts, and a scanner exception SHALL be treated as a validation failure (block), never as fail-open.

#### Scenario: No dead config keys
- **WHEN** an operator sets a documented config key (e.g. enabling archive/office scanning, blocking dangerous types, or GPS blocking)
- **THEN** the corresponding behavior SHALL change accordingly

#### Scenario: Works in queue/CLI context
- **WHEN** validation runs without a bound HTTP request (queue, CLI, test)
- **THEN** scanners SHALL NOT throw from unguarded `config()`/`logger()`/`request()` calls

#### Scenario: Scanner exception blocks the file
- **WHEN** a scanner throws an unexpected exception
- **THEN** the caller SHALL treat the result as a failure and reject the file

### Requirement: Upload Rate and Size Limiting

The system SHALL provide a configurable DoS guard that limits per-upload size and upload frequency (files-per-minute and total-bytes-per-minute), SHALL reject over-limit uploads fail-closed, and SHALL degrade safely when no HTTP request context is available.

#### Scenario: Oversize upload is rejected
- **WHEN** an upload exceeds the configured maximum file size for scanning
- **THEN** it SHALL be rejected rather than scanned

#### Scenario: Per-minute cap is enforced with bounded work
- **WHEN** uploads exceed the configured files-per-minute or total-bytes-per-minute limit
- **THEN** further uploads in the window SHALL be rejected by the rate guard with bounded work

#### Scenario: Non-HTTP context does not crash the limiter
- **WHEN** validation runs without a bound request (queue/CLI)
- **THEN** the rate guard SHALL skip request-keyed limits without throwing while still enforcing the size limit

