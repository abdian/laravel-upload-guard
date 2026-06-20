# Tasks: Harden Laravel Safeguard to a Production-Ready Release

Ordered for safe, verifiable progress. Each phase ends with tests. Do not start implementation until the proposal is approved. Spec deltas referenced per phase live under `specs/<capability>/spec.md`.

## 1. Test harness & safety net (do this first)
- [x] 1.1 Add `orchestra/testbench` Testbench base test case; switch `phpunit.xml` to collect `tests/` (Feature + Unit) and set a coverage floor (start at current, ratchet up).
- [x] 1.2 Create a malicious-fixture library under `tests/Fixtures/` (generated programmatically, never executable on disk): PHP-in-JPEG/PNG/GIF/PDF/ZIP polyglots, `octet-stream` polyglot, unquoted-handler SVG, external-DTD/PUBLIC XXE SVG, forged-central-directory zip bomb, classic 42.zip-style bomb, legacy-OLE `Auto_Open` doc, lowercase-`[content_types].xml` docx, FlateDecode/`#xx` PDF JavaScript, `/OpenAction` PDF, decompression-bomb PNG (50000×50000 header), double-extension/ADS/whitespace archive entries.
- [x] 1.3 Write **failing** regression tests for every confirmed bypass (red) so the fixes turn them green. (Capability: `release-readiness`.)
- [x] 1.4 CI: add `.github/workflows/tests.yml` — matrix PHP {8.1,8.2,8.3,8.4} × Laravel {10,11,12} via Testbench {8,9,10}, `setup-php` with `ext-fileinfo,zip,exif,gd,dom`, run phpunit + coverage + PHPStan + `composer validate --strict`. (Capabilities: `framework-compatibility`, `release-readiness`.)
- [x] 1.5 Add `phpstan.neon` (paths: `src`; start at an achievable level and ratchet up) and `phpstan/phpstan` to `require-dev`; make the static-analysis run green and wire it into CI as a release gate. (Capability: `release-readiness`.)

## 2. MIME detection — structural & fail-closed (`mime-detection`)
- [x] 2.1 Read a configurable header window (default ≥512B) and memoize `detect()` per file; fix the duplicate signature-table key.
- [x] 2.2 Disambiguate OLE compound subtypes (doc/xls/ppt/msg via storage names), `ftyp` brands (mp4/mov/m4a/heic/avif), RIFF (webp/avi/wav), ZIP families (office/jar/apk/epub/odf).
- [x] 2.3 Structurally validate short signatures (BMP size@2 + DIB@14, etc.); detect JAR/APK as `application/java-archive` and add it to the hard-coded dangerous default.
- [x] 2.4 Make `detect()` return `null` for unknown and ensure callers treat `null` as untrusted (never "binary safe"); align `isBinaryFile()`/`isDangerous()` defaults with shipped config.
- [x] 2.5 Fix `ExtensionMimeMap` gaps surfaced by detector outputs (WMA/WMV, AVIF/HEIC, legacy `.xls`/`.ppt`, `.js`/`.css`, single `.gz`/`.bz2`, 7z). Tests: real `.xls`/`.ppt`/JAR/WMA round-trip + appended-data polyglot classification.

## 3. PHP threat scanning — always-on & obfuscation-resistant (`php-threat-scanning`)
- [x] 3.1 Remove the `isBinaryFile()` early-exit; scan raw bytes for all PHP/script openers on every upload; remove `application/octet-stream` from the binary allowlist.
- [x] 3.2 Add openers: bare `<?` (except `<?xml`), `<?=`, `<script language=php>`, `<%`, `__halt_compiler`; flag any opener unconditionally.
- [x] 3.3 Gate function/keyword analysis on an actual PHP open-tag region (eliminate `.js`/`.py`/`.md`/`.csv`/`.sql` false positives); when deep analysis is enabled, use `token_get_all()` under a size cap to catch dynamic dispatch / variable functions / backtick exec.
- [x] 3.4 Make `strict` mode a superset of `default`; error/warn on empty `custom` `scan_functions`. Tests: polyglot RCE blocked across all binary types; benign source files pass; obfuscated dispatch flagged.

## 4. SVG sanitization (`svg-sanitization`)
- [x] 4.1 Add `enshrined/svg-sanitizer` (or vetted equivalent); replace regex scanning with allowlist sanitization; return/persist the cleaned SVG.
- [x] 4.2 Reject/strip all DOCTYPE/DTD/entities (internal subset or not, any scheme, SYSTEM or PUBLIC); install `libxml_set_external_entity_loader` deny + `LIBXML_NONET` for any package XML parsing.
- [x] 4.3 Ensure case/encoding-insensitive handling and that benign standard elements are not over-rejected. Tests: unquoted-handler XSS, leading-whitespace `javascript:`, external-DTD XXE all neutralized; benign SVG passes unchanged in meaning.

## 5. PDF threat scanning (`pdf-threat-scanning`)
- [x] 5.1 Add `smalot/pdfparser` (or inline inflater fallback); inflate Flate/LZW/ASCII85/ASCIIHex streams and parse `/ObjStm`; decode `#xx` names; resolve indirect refs before matching.
- [x] 5.2 Detect `/OpenAction` and `/AA`; anchor action/name matches on PDF delimiters; remove substring false positives (`javascript.info`, `/Sounds`, `/Movies`).
- [x] 5.3 Handle encrypted PDFs (decrypt with empty/owner password or quarantine); remove the `>1 /Encrypt` heuristic.
- [x] 5.4 Count pages from the catalog page tree `/Count` after inflation; on indeterminate count, skip + log instead of hard-fail; route `SafeguardPages` through `ValidatesFileAccess` and honor `pdf_scanning.enabled`. Tests: compressed/hex JS detected; PDF polyglot blocked; compressed PDF page count correct; injected `/Type /Page` tokens ignored.

## 6. Archive threat scanning (`archive-threat-scanning`)
- [x] 6.1 Stream-decompress each entry through a bounded reader; enforce a hard global byte cap on **actual** decompressed bytes; flag declared-vs-actual size mismatch; never trust `statIndex()['size']`.
- [x] 6.2 Check every dotted segment of each entry name; normalize trailing whitespace/dots/control chars and NTFS ADS; detect `\` and `/` traversal and absolute paths; reject symlink/hardlink entries (zip external attrs / tar typeflag).
- [x] 6.3 Complete the blocklist (`.pht`,`.phtml`,`.shtml`,`.htaccess`,`.inc`,`web.config`, …); actually recurse nested archives within the depth cap; reject detected-but-unsupported/encrypted formats (ISO/CAB/encrypted) instead of passing. Tests: forged-size + classic zip bomb blocked; double-ext/ADS/whitespace/backslash entries blocked; symlink entry blocked; nested archive scanned.

## 7. Office document scanning (`office-document-scanning`)
- [x] 7.1 Add legacy OLE/CFB (`D0CF11E0`) macro/OLE detection alongside OOXML; fail closed when `blockMacros` is on and the container can't be fully parsed.
- [x] 7.2 Look up OPC parts case-insensitively; resolve VBA/OLE/ActiveX via `.rels` relationships and `[Content_Types].xml`, not filename patterns; detect renamed VBA storage.
- [x] 7.3 Fix `loadConfiguration()` so it does not overwrite explicit fluent flags. Tests: legacy `.doc` macro blocked; lowercase-`[content_types].xml` docx scanned; `allowMacros()` honored.

## 8. Image threat scanning (`image-threat-scanning`)
- [x] 8.1 Enforce pixel-count + byte caps from the header **before** any decode/strip; reject oversize images.
- [x] 8.2 Scan all EXIF/IFD sections and the `COMMENT` array; run the full PHP byte-scanner on image content; work without `ext-exif` (skip EXIF, still scan bytes — never reject all images on missing extension).
- [x] 8.3 Structural trailing-data detection (no 100-byte threshold; robust GIF trailer); add optional recommended `reencode` mode (GD/Imagick) and make strip support all advertised formats or fail loudly. Tests: decompression-bomb PNG rejected pre-decode; `<?` in `Make`/`COMMENT` detected; trailing payload detected; re-encode strips payload; user-facing `SafeguardDimensions` min/max still enforced.

## 9. Orchestration, config & robustness (`upload-orchestration`)
- [x] 9.1 `safeguard` enables archive/office from config; routes by content-derived type with case-insensitive extension as secondary; fails closed when detected type is `null` or a recognized container is unhandled.
- [x] 9.2 Single-pass pipeline: read/decode once and share across sub-scanners; add `max_scan_size` cap with a defined over-cap policy; replace `preg_match_all` with `preg_match` where boolean suffices.
- [x] 9.3 Guard bare `config()`/`logger()`/`request()` in all scanners/rules; ensure scanner exceptions are treated as block (fail-closed) by callers.
- [x] 9.4 Wire every documented config key to behavior; remove/deprecate dead keys with fail-closed defaults; validate user-supplied regex at config load (drop `@`-suppression). Tests: default `safeguard` blocks zip-traversal + macro docx; uppercase `.SVG`/`.PDF` routed correctly; queue/CLI context does not throw; large upload bounded.
- [x] 9.5 Add an upload rate/size DoS guard: `max_file_size`, `max_files_per_minute`, `max_total_size_per_minute`; reject over-limit fail-closed; guard for non-HTTP contexts (skip request-keyed limits, still enforce size). Tests: over-size rejected; per-minute cap enforced with a bounded limiter; CLI context skips rate keying without throwing.
- [x] 9.6 Produce a config-migration map (old key → new behavior): deprecate `archive_scanning.max_compression_ratio` (superseded by the actual-decompressed-bytes cap from 6.1); define the new SVG sanitizer config surface (allowlist) replacing the now-dead `svg_scanning` blocklist keys; clarify `archive_scanning.rar_fail_open` / RAR/7z handling (reject when contents cannot be stream-inspected); add the new keys (`max_scan_size`, header-window size, image pixel/byte caps, `reencode`, `quarantine.*`, `rate_limiting.*`). This map feeds `UPGRADE.md` (13.5).

## 10. File access validation (`file-access-validation`)
- [x] 10.1 Trailing-separator prefix comparison (no sibling-prefix bypass); fail closed on empty allow-list; null-byte check first; include `ini_get('upload_tmp_dir')` in defaults.
- [x] 10.2 Add a destination-path validation helper for the move/store step; document that the trait alone does not close the temp→storage TOCTOU window. Tests: `/storage/app-evil` rejected; empty allow-list rejects; null-byte path handled without `ValueError`.

## 11. Security logging (`security-logging`)
- [x] 11.1 Route all threat events through `SecurityLogger`; honor `logging.enabled/channel/detailed/hash_algorithm`; guard `hash_file` (only when realpath readable); wrap the log body in try/catch; validate/fallback the channel.
- [x] 11.2 Sanitize attacker-controlled strings (filenames, metadata): strip control chars, cap length (anti log-injection). Tests: unresolved realpath logs without crashing; CRLF filename sanitized; logging failure never breaks validation.
- [x] 11.3 Add opt-in quarantine: when `quarantine.enabled`, copy a rejected file to `quarantine.path` with a sanitized JSON metadata sidecar; config-driven retention; wrap writes in try/catch so a quarantine failure never breaks validation or fails open. Tests: disabled by default (no copy); enabled path writes file + sanitized metadata; write failure does not crash or fail-open.

## 12. Framework compatibility & performance (`framework-compatibility`)
- [x] 12.1 `composer.json`: require `ext-fileinfo`, `ext-zip`, `ext-exif`, `ext-dom` and the Illuminate components actually used; guard each optional extension with `class_exists`/`function_exists` and document safe degradation; remove `minimum-stability=dev`.
- [x] 12.2 Verify the public API across Laravel 10/11/12 + PHP 8.1–8.4 (green matrix from 1.4).
- [x] 12.3 Add `tests/Performance` benchmarks asserting bounded time/memory for representative and adversarial inputs; document the performance budget.
- [x] 12.4 Declare the new library dependencies in `composer.json` `require` with pinned minimums (`smalot/pdfparser`, `enshrined/svg-sanitizer`); regenerate `composer.lock`; confirm the CI matrix (1.4) installs cleanly on every PHP 8.1–8.4 × Laravel 10/11/12 pair; keep the inline PDF-inflater fallback (`class_exists`-guarded) for when the parser is absent.

## 13. Release readiness — docs, packaging, security policy (`release-readiness`) — LAST
- [x] 13.1 Add `.gitattributes` with `export-ignore` for `tests/`, `docs/`, `openspec/`, `.github/`, `.idea/`, `.phpunit.cache/`, `coverage/`, `node_modules`, `package*.json`, `phpunit.xml`, `phpstan.neon`, `composer.lock`, `AGENTS.md`, `CLAUDE.md`, `DOCUMENTATION_SETUP.md`, and dev scripts; add `coverage/` and `.phpunit.cache/` to `.gitignore`; **delete** `comprehensive_test.php`, `test_mimes_integration.php`, `fixes.md`, `DOCUMENTATION_SETUP.md` (after porting useful content/tests).
- [x] 13.2 Rewrite `README.md` to match actual behavior (no overpromising): accurate feature list, security guarantees and limitations, required extensions, supported Laravel/PHP, default-on scanners, performance notes.
- [x] 13.3 Rebuild the VitePress `docs/` (guide + API + security pages) and `src/config/safeguard.php` comments to match the new config and behavior; remove dead-key docs.
- [x] 13.4 Add `SECURITY.md` with a real, monitored disclosure contact; replace `security@example.com` placeholders in README/CONTRIBUTING.
- [x] 13.5 Add `UPGRADE.md` migration guide (breaking behavior + config migration from 9.6, for existing dev-tracking users) and update `CHANGELOG.md`; move fixes out of `[Unreleased]` into a `1.0.0` section.
- [x] 13.6 Update `openspec/project.md` to reflect the new architecture; final `composer validate --strict`, full green matrix, coverage floor met, PHPStan green; tag the `1.0.0` stable release.

## 14. Final verification
- [x] 14.1 Every regression test from 1.3 is green; no skipped security tests.
- [x] 14.2 `openspec validate prepare-production-release --strict` passes; archive this change, then archive `add-security-enhancements` with `--skip-specs` (its capabilities are superseded by this change's specs — avoid creating duplicate capability trees in `specs/`).
