# framework-compatibility Specification

## Purpose
TBD - created by archiving change prepare-production-release. Update Purpose after archive.
## Requirements
### Requirement: Laravel 10/11/12/13 and PHP 8.1–8.5 Support

The system SHALL support Laravel 10.x, 11.x, 12.x, and 13.x on PHP 8.1 through 8.5 from a single codebase, and a CI matrix SHALL prove the public API and rules work on every supported combination. The package's own PHP floor is 8.1; Laravel 13.x requires PHP 8.3+ per the framework's support policy, so Composer resolves Laravel ≤12 on PHP 8.1–8.2 and Laravel 13 on PHP 8.3+.

#### Scenario: Test matrix is green across versions
- **WHEN** the CI matrix runs PHP {8.1,8.2,8.3,8.4,8.5} × Laravel {10,11,12,13} (via Testbench {8,9,10,11}, excluding unsupported pairs such as Laravel 13 on PHP < 8.3 or Laravel ≤11 on PHP 8.5)
- **THEN** the full test suite SHALL pass on each supported combination

### Requirement: Declared Runtime Dependencies and Safe Degradation

The system SHALL declare its hard runtime extensions in `composer.json` (`ext-fileinfo`, `ext-zip`, `ext-exif`, `ext-dom`) and the Illuminate components it uses, and SHALL guard optional extensions so their absence degrades safely instead of crashing or rejecting all files.

#### Scenario: Missing ext-zip does not crash
- **WHEN** `ext-zip` is unavailable and an archive/Office file is validated
- **THEN** the code SHALL guard `ZipArchive` usage with `class_exists` and handle the absence per the fail-closed policy rather than throwing an uncaught fatal

#### Scenario: Missing ext-exif still validates images
- **WHEN** `ext-exif` is unavailable
- **THEN** image validation SHALL proceed (byte scanning + dimension guard) without rejecting every image

### Requirement: Bounded Performance Budget

The system SHALL bound per-file work to a single header read plus at most one full-content pass (format scanners operating on already-decoded structures), enforce a configurable maximum scan size, and a benchmark SHALL guard against performance/memory regressions.

#### Scenario: Adversarial input stays bounded
- **WHEN** the benchmark validates large and adversarial inputs (within the scan-size cap)
- **THEN** time and memory SHALL stay within the documented budget
- **AND** inputs beyond the cap SHALL be rejected/header-only rather than scanned unbounded

