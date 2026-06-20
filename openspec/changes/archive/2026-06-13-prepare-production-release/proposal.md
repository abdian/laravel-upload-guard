# Change: Harden Laravel Safeguard to a Production-Ready, Fail-Closed Release

## Why

A full audit (independent code review + a 23-agent adversarial red-team with executable PoCs) found that the package, in its current state, **advertises protection it does not deliver** and is **not safe to ship**. The detection architecture is "regex/substring over raw bytes" with a `binary → skip` early-exit, which is defeated by trivial polyglots and by every format that compresses, encrypts, or escapes its payload.

Confirmed, reproduced issues (severity):

- **CRITICAL** — `PhpCodeScanner` returns `safe` for any file detected as image/PDF/zip/`octet-stream` (`isBinaryFile()` early-exit), so a web shell appended after a valid magic header is never scanned → stored-file RCE.
- **CRITICAL** — PDF JavaScript / `/OpenAction` payloads pass when compressed (`FlateDecode`/`ObjStm`) or hex-name-escaped (`/J#61vaScript`); a `%PDF`+`<?php` polyglot passes the all-in-one rule entirely.
- **CRITICAL** — SVG XSS via **unquoted** event handlers (`<svg onload=alert(1)>`) and leading-whitespace `javascript:` URIs passes; the scanner only detects, never sanitizes, and the file is stored/served verbatim.
- **HIGH** — Default `required|safeguard` silently **skips archive and Office-macro scanning** (gated behind fluent calls that default off), contradicting the README; zip-bomb checks trust **forgeable** central-directory sizes (42.zip-class bombs pass); legacy OLE Office macros and case-variant OOXML bypass detection; external-DTD XXE is undetected; PHP short tags / obfuscation evade detection.
- **HIGH/MEDIUM** — Large numbers of **false positives** reject legitimate files (real `.xls`/`.ppt` via OLE→msword mis-detection, `.js`/`.py`/`.csv` text, compressed PDFs, benign SVG elements); `composer.json` under-declares required extensions so installs silently degrade or reject all images.
- **Production readiness** — test coverage is **5.18%** (only `MimeTypeDetector`; 20 classes at 0%); dev/debug artifacts ship in the Composer dist; `minimum-stability=dev`; CI runs only docs; placeholder security contact; many documented config keys are dead.

This change re-architects detection to **fail closed**, replaces brittle pattern-matching with structural parsing (and SVG sanitization), eliminates the false positives, adds a real test suite and CI matrix across Laravel 10/11/12, optimizes for single-pass performance, and rebuilds the README/docs/packaging so the published behavior matches reality.

## What Changes

### Detection architecture (**BREAKING** behavior)
- **Always** scan raw bytes for PHP/script openers regardless of detected MIME; remove the `binary → skip` early-exit and drop `application/octet-stream` from the "safe binary" allowlist.
- Replace SVG regex detection with an **allowlist sanitizer**; the sanitized output is what gets stored. Reject/strip all DTD/DOCTYPE/entities and disable external-entity loading.
- Parse PDFs with a real decoder: inflate streams, parse `/ObjStm`, decode `#xx` names; cover `/OpenAction` and `/AA`; handle encrypted PDFs; count pages from the catalog page tree.
- Stream-decompress archives against a **hard byte cap** (real zip-bomb detection); check every name segment; normalize ADS/whitespace/backslash; reject symlink entries; complete the dangerous-extension blocklist; recurse nested archives.
- Office scanning covers legacy OLE/CFB, looks parts up case-insensitively, and resolves macros/OLE/ActiveX via relationships; fail closed on unparsable containers.
- Image scanning enforces a decompression-bomb guard before decode, scans all metadata sections, and (optionally, recommended) re-encodes uploads to strip payloads.
- MIME detection reads a larger window, disambiguates OLE/ftyp/RIFF/ZIP subtypes (fixes `.xls`→msword), detects JAR/APK, structurally validates short signatures, memoizes, and returns `null` → **fail closed** (never "binary safe").

### Orchestration, config & robustness
- The `safeguard` all-in-one rule enables archive/office scanning from config, routes case-insensitively by content+extension, fails closed on unknown/unhandled containers, runs as a **single-pass pipeline** with a configurable max scan size, and treats scanner exceptions as block (never fail-open). Guard bare `config()`/`logger()`/`request()`.
- Wire every documented config key to real behavior; remove dead keys; fail-closed defaults.
- Route all threat logging through a hardened `SecurityLogger` (guarded hashing, validated channel, sanitized context).
- Fix `ValidatesFileAccess` (trailing-separator prefix, fail-closed empty allowlist, null-byte first, `upload_tmp_dir`); reframe TOCTOU scope and add a destination-path validation helper.
- Add an **upload rate/size DoS guard** (max file size, files-per-minute, total-bytes-per-minute) that fails closed on over-limit and degrades safely without an HTTP request.
- Add an **opt-in quarantine** of rejected files (disabled by default) that copies the file plus a sanitized metadata sidecar via `SecurityLogger`, with config-driven retention and crash-safe writes.

### Compatibility, performance, tests, release
- Support Laravel 10/11/12 and PHP 8.1–8.4; **declare** `ext-fileinfo`, `ext-zip`, `ext-exif`, `ext-dom` (and used Illuminate components); guard optional extensions to degrade safely.
- **Declare the new library dependencies** (`smalot/pdfparser`, `enshrined/svg-sanitizer`) with pinned minimums in `composer.json`, regenerate `composer.lock`, and verify they install across the full PHP 8.1–8.4 × Laravel 10/11/12 matrix (keep a `class_exists`-guarded inline PDF-inflater fallback if the dependency is rejected).
- Add **static analysis** (PHPStan/Psalm) via `phpstan.neon` over `src/`, run as a CI release gate.
- Single-read pipeline + max scan size + bounded passes; documented performance budget and a benchmark guard.
- Comprehensive Testbench test suite with malicious fixtures and a regression test for every confirmed bypass; CI matrix + coverage floor + `composer validate --strict`.
- **At the end:** rebuild README, the VitePress docs, CHANGELOG, and config comments to match actual behavior; add `SECURITY.md` with a real contact and an `UPGRADE.md` migration guide; add `.gitattributes export-ignore`; remove dev artifacts; drop `minimum-stability=dev`; cut the tagged **`1.0.0`** stable release.

## Impact

- **Affected specs (new capabilities):** `mime-detection`, `php-threat-scanning`, `svg-sanitization`, `pdf-threat-scanning`, `archive-threat-scanning`, `office-document-scanning`, `image-threat-scanning`, `upload-orchestration`, `file-access-validation`, `security-logging`, `framework-compatibility`, `release-readiness`.
- **Affected code:** every scanner in `src/`, every rule in `src/Rules/`, `src/MimeTypeDetector.php`, `src/ExtensionMimeMap.php`, `src/Concerns/ValidatesFileAccess.php`, `src/SecurityLogger.php`, `src/SafeguardServiceProvider.php`, `src/config/safeguard.php`, `composer.json`, `phpunit.xml`, `tests/`, `.github/workflows/`, `README.md`, `docs/`, `CHANGELOG.md`, new `SECURITY.md`/`UPGRADE.md`/`.gitattributes`/`phpstan.neon`, new quarantine + rate-limiting config/code, and the new Composer dependencies (`smalot/pdfparser`, `enshrined/svg-sanitizer`).
- **Relationship to `add-security-enhancements`:** that pending change introduced the archive/office/XXE/symlink/zip-bomb features; this change **hardens and corrects** them (their current implementations contain the confirmed bypasses). Sequence: land this change's fixes, then archive both.

## Breaking Changes

This is the **first stable release (`1.0.0`)** — there is no prior tagged release (the package was only installable at `minimum-stability=dev`), so `UPGRADE.md` targets existing dev-tracking users. Stricter, fail-closed behavior will (intentionally) reject files the pre-1.0 code accepts, and may change accepted files (SVG sanitized/rewritten, images optionally re-encoded). Documented in `UPGRADE.md`:

- Polyglots, compressed/encrypted PDFs with active content, forged-size archives, legacy-macro Office docs, and DTD-bearing SVGs are now rejected.
- Default `safeguard` now performs archive + Office scanning.
- Some previously-rejected legitimate files (real `.xls`/`.ppt`, `.js`/`.csv`, compressed PDFs) are now accepted.
- New required PHP extensions must be present (or features degrade with documented behavior).

## Risk Assessment

| Area | Severity if unfixed | Effort | Implementation risk |
|------|---------------------|--------|---------------------|
| PHP polyglot RCE (always-scan) | Critical | Medium | Low |
| PDF decode-before-scan | Critical | High | Medium |
| SVG sanitization | Critical | Medium | Low |
| Archive streaming/zip-bomb | High | High | Medium |
| Office OLE + case-insensitive | High | Medium | Low |
| Image decompression-bomb | High | Low | Low |
| MIME disambiguation / false positives | High | Medium | Medium |
| Orchestration fail-closed + perf | High | Medium | Medium |
| Tests / CI / packaging / docs | High | High | Low |

## Out of Scope

- Antivirus/ClamAV integration, sandboxed detonation, and ML-based detection (may be proposed later).
- New file formats beyond those already advertised.
- Async/queued scanning architecture (single-pass synchronous validation is retained).

### Deferred to a later release (tracked, intentionally not in 1.0.0)

These items from the internal roadmap (`fixes.md`) are deliberately excluded from 1.0.0 — recorded here so the exclusion is a conscious decision, not an oversight:

- Event/Hook system (`FileScanning`/`FileScanned`/`ThreatDetected` events).
- Media (video/audio) metadata scanning (`MediaScanner`).
- WebAssembly (`.wasm`) detection.
- Custom exception hierarchy (`SafeguardException`, …) and `SafeguardServiceProvider` registration de-duplication (internal refactors; behavior unchanged).
- Artisan commands (`safeguard:rules`, `safeguard:scan`, `safeguard:quarantine:clean`) — quarantine retention is config-driven and does not require them.
