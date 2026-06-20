# Changelog

All notable changes to Laravel Upload Guard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-21

First **stable** release. The package was previously only installable at
`minimum-stability=dev`; this release re-architects detection to be fail-closed
and production-ready. Runs on **Laravel 10–13** and **PHP 8.1–8.5** (Laravel 13
requires PHP 8.3+). See [UPGRADE.md](UPGRADE.md) for behavior/config changes.

### Security (breaking, fail-closed)

- **Hardened against an independent red-team pass** (70+ novel hand-crafted
  attacks). Closed confirmed bypasses: PHP/ASP/JSP short-tag openers (`<?{`,
  `<?;`, `<%eval`), archive fail-open beyond the max nesting depth, un-scanned
  **compressed** archive content (deflated web shells), TAR ustar-prefix and GNU
  LongLink path traversal, DDE/formula injection in non-Word OOXML parts (xlsx),
  remote references inside SVG `<style>` CSS, absolute/`file:` SVG hrefs, UTF-16
  SVGs, TIFF/BigTIFF decompression bombs, image content-sniffing polyglots,
  comment-prefixed HTML XSS, dangerous top-level extensions
  (`.hta/.scf/.lnk/.iqy/.slk/…`), embedded OLE/DDE objects in RTF, and
  macro-bearing legacy OLE files with no recognized document subtype.
  **HTML is a blocked content type by default**
  (allowlist it via `mimes`/`allowedMimes()` if you accept HTML). See the README
  **"Limitations & not a security boundary"** for residual, intentionally-
  uncovered gaps — Upload Guard is defense-in-depth, not a guarantee.
- **Always-on code scanning.** PHP/script openers (`<?php`, `<?=`, bare `<?`,
  `<script language=php>`, `<%`, `__halt_compiler`) are scanned on **every**
  upload regardless of detected type. The `binary → skip` early-exit and the
  `application/octet-stream` "safe" allowlist were removed — polyglot web shells
  appended to images/PDFs/ZIPs are now detected (stored-file RCE class).
- **SVG sanitization** via an allowlist sanitizer (`enshrined/svg-sanitize`); the
  cleaned SVG is what gets stored. Unquoted handlers, whitespace/encoded
  `javascript:` URIs, `<script>`, and all DTD/DOCTYPE/entities are removed or the
  file is rejected. XML parsing installs a denying external-entity loader.
- **PDF decode-before-scan.** Flate/LZW/ASCII85/ASCIIHex streams and object
  streams (`/ObjStm`) are inflated and `#xx` names decoded before matching.
  `/OpenAction` and `/AA` auto-run triggers are covered; matches are anchored on
  PDF delimiters and case-sensitive (no more `javascript.info`/`/Sounds` false
  positives). Encrypted PDFs that cannot be inspected are rejected. Indirect
  `/Filter` references and oversized stream dictionaries are resolved (compressed
  JavaScript cannot hide behind a decoy/indirect filter), stream inflation is
  bounded against the scan budget, and — when the parser is available — decoded
  objects are added to the scan surface (fail-closed: coverage never drops).
- **Real zip-bomb detection.** Archives are stream-decompressed against a hard
  cap on **actual** bytes that is **global across the whole nested-archive tree**,
  so nested fan-out cannot multiply the budget; forged central-directory/TAR sizes
  no longer bypass it. Every dotted name segment is checked; traversal (both
  separators), absolute paths, NTFS ADS, and symlink/hardlink entries are
  rejected; nested archives are recursed; unreadable entries and unsupported/
  encrypted formats fail closed.
- **Office macros (OLE + OOXML) + macro-less vectors.** Legacy OLE/CFB
  (`.doc/.xls/.ppt`) macro storages are detected alongside OOXML; parts are
  matched case-insensitively and macros/OLE/ActiveX are resolved via relationships
  and `[Content_Types].xml` (renamed VBA storages caught). `DDE`/`DDEAUTO` field
  codes (across all WordprocessingML story parts) and external/remote-template
  relationships (`attachedTemplate`/OLE with `TargetMode="External"`) are flagged;
  the CFB reader follows the full DIFAT chain and fails closed on truncated or
  unparsable containers.
- **Image decompression-bomb guard** enforced from the header **before** any
  decode — including inside the re-encode path itself (GD or Imagick backend);
  full EXIF/IFD + `COMMENT` and byte scanning (works without `ext-exif`);
  structural trailing-data detection; optional re-encode mode that strips
  payloads.
- **Structural, fail-closed MIME detection.** Larger header window, OLE/ftyp/RIFF/
  ZIP-family disambiguation (real `.xls` → `vnd.ms-excel`, JAR/APK detection),
  short-signature structural validation, memoization, and `null` (untrusted) for
  unknown content — never "binary safe".

### Added

- DoS guard: configurable per-file size and per-IP per-minute file/byte limits.
- Opt-in quarantine of rejected files with a sanitized JSON metadata sidecar.
- Hardened, crash-safe `SecurityLogger` (guarded hashing, validated channel,
  log-injection-safe context) used by every scanner.
- `ValidatesFileAccess` destination-path helper for the temp→storage move.
- PHPStan static-analysis gate, a CI matrix across Laravel 10/11/12/13 × PHP
  8.1–8.5, a Testbench test suite with malicious fixtures, and a coverage floor.
- New dependencies: `smalot/pdfparser`, `enshrined/svg-sanitize`. Required
  extensions: `ext-fileinfo`, `ext-zip`, `ext-dom`, `ext-libxml`; `ext-exif`,
  `ext-gd`, and `ext-imagick` are optional (suggested) — scanners degrade
  gracefully without them.
- Worker-safe hardening for Octane/queue: atomic rate-limiter counters, a bounded
  MIME-detection cache, quarantine files written `0600`, and per-instance archive
  rule overrides restored after every validation (no cross-request config leak).

### Changed

- Default `safeguard` rule now performs archive **and** Office scanning without
  fluent `scanArchives()` / `blockMacros()` calls.
- Scanner exceptions are treated as a validation failure (never fail-open).
- `loadConfiguration()` no longer overwrites explicit fluent flags
  (`allowMacros()` etc.).
- `minimum-stability` is now `stable`.
- Test suite migrated from `@dataProvider` doc-comments to the `#[DataProvider]`
  attribute (PHPUnit 12 removed doc-comment metadata); runs on PHPUnit 10–13.

### Removed

- Dev/debug scripts and dead configuration keys (see UPGRADE.md). The legacy
  `svg_scanning` blocklist keys and `archive_scanning.max_compression_ratio` are
  superseded.

[1.0.0]: https://github.com/abdian/laravel-upload-guard/releases/tag/v1.0.0
