# Release Readiness

## ADDED Requirements

### Requirement: Comprehensive Test Suite with Malicious Fixtures

The system SHALL ship a test suite that exercises every scanner and the orchestrator against known-good and known-malicious fixtures, includes a regression test for every confirmed historical bypass, and enforces a coverage floor in CI.

#### Scenario: Each confirmed bypass has a regression test
- **WHEN** the suite runs
- **THEN** there SHALL be a test for each confirmed bypass (polyglot RCE, compressed/hex PDF JS, unquoted-handler SVG, external-DTD XXE, forged-size zip bomb, legacy/case-variant Office macro, decompression-bomb image)
- **AND** each SHALL fail against the pre-fix behavior and pass against the fixed behavior

#### Scenario: Coverage floor is enforced
- **WHEN** CI runs
- **THEN** the build SHALL fail if coverage drops below the configured floor

### Requirement: Clean, Validated Distribution

The Composer distribution SHALL exclude tests, docs, OpenSpec, and dev artifacts via `.gitattributes export-ignore`; dev/debug scripts SHALL be removed (after porting useful tests); `minimum-stability` SHALL NOT be `dev`; and `composer validate --strict` SHALL pass.

#### Scenario: Dev artifacts are not shipped
- **WHEN** the package is installed via `composer require`
- **THEN** `comprehensive_test.php`, `test_mimes_integration.php`, `fixes.md`, `DOCUMENTATION_SETUP.md`, the `docs/` site, and `node` artifacts SHALL NOT be present in the installed package

### Requirement: Documentation, Security Policy, and Versioning Match Behavior

The README, docs site, CHANGELOG, and config comments SHALL describe only the package's actual behavior (including limitations and required extensions), a `SECURITY.md` with a real disclosure contact SHALL exist, an `UPGRADE.md` SHALL document the breaking behavior and config migration, and the breaking changes SHALL be released as the first stable tag (`1.0.0`, replacing dev-only installs).

#### Scenario: README claims match code
- **WHEN** the README states that the single `safeguard` rule runs a set of checks
- **THEN** those checks SHALL actually run by default in the code (or the README SHALL be corrected to state the required fluent calls)

#### Scenario: Security contact is real
- **WHEN** a reporter follows the security policy
- **THEN** the contact SHALL be a monitored address, not a placeholder such as `security@example.com`

#### Scenario: Breaking changes are versioned and documented
- **WHEN** the hardened behavior is released
- **THEN** it SHALL be the first stable release (`1.0.0`, replacing dev-only installs) with an `UPGRADE.md` enumerating the behavior and configuration changes

### Requirement: CI Release Gating

A CI workflow SHALL run the test suite, coverage, static analysis, and `composer validate --strict` across the supported version matrix and SHALL gate releases on success.

#### Scenario: Release is gated on green CI
- **WHEN** a release is prepared
- **THEN** it SHALL proceed only if the matrix build, coverage floor, static analysis, and `composer validate --strict` all pass

### Requirement: Static Analysis Gate

The package SHALL include a static-analysis configuration (`phpstan.neon`, or a Psalm equivalent) over `src`, and CI SHALL run it as a release gate so type/logic regressions fail the build.

#### Scenario: Static analysis runs in CI
- **WHEN** CI runs for a release
- **THEN** static analysis SHALL execute over `src` and the build SHALL fail if it reports errors above the configured baseline
