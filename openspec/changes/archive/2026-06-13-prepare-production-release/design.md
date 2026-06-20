## Context

Laravel Safeguard validates uploaded files for malicious content. An audit reproduced multiple end-to-end bypasses (PHP polyglot RCE, compressed/escaped PDF JS, unquoted-handler SVG XSS, forged-size zip bombs, legacy/case-variant Office macros, external-DTD XXE) plus many false positives, near-zero test coverage, and packaging defects. The root cause is architectural: detection is substring/regex over the raw bytes of a file whose real structure is never parsed, combined with a `binary → trust` early-exit. This document records the decisions needed to move to a fail-closed, structurally-grounded, production-ready package without leaving blind spots.

Constraints:
- Must remain a pure validation library (synchronous, runs inside Laravel's validator) — no daemon, no external AV requirement.
- Must support Laravel 10/11/12 and PHP 8.1–8.4 from a single codebase.
- Must minimize per-request overhead (uploads are request-path) and bound memory.
- Stricter behavior is acceptable and expected (semver-major), but must not gratuitously reject legitimate files.

## Goals / Non-Goals

**Goals**
- Fail closed by default: when the package cannot be sure a file is safe, it blocks.
- Defeat the confirmed bypasses with structural parsing, not more regex.
- Eliminate the confirmed false positives.
- One scan pass per upload; bounded CPU and memory.
- Green CI across the full Laravel/PHP support matrix; meaningful coverage with malicious fixtures.
- Published README/docs/config that exactly match behavior.

**Non-Goals**
- AV signature scanning, sandboxed detonation, ML classification.
- Asynchronous/queued scanning.
- Supporting unmaintained PHP/Laravel versions.

## Decisions

### D1 — Fail-closed is the governing principle
Every ambiguous outcome (unknown MIME, missing extension, unparsable container, scanner exception, indeterminate result) resolves to "reject" for security-relevant checks, and to "skip the check but do not pass the file as safe" for availability-only checks (e.g., page count). Scanner exceptions are caught by callers and treated as a failure, never swallowed as "allow".
- Alternative considered: best-effort/fail-open (current behavior). Rejected — it is the direct cause of the RCE-class bypasses.

### D2 — Always scan bytes for code; `isBinaryFile()` is a hint, not a gate
A lightweight full-content scan for PHP/script openers (`<?php`, `<?=`, bare `<?` except `<?xml`, `<script language=php>`, `<%`, `__halt_compiler`) runs on **every** upload regardless of detected type. `application/octet-stream` is removed from the "safe binary" allowlist. Deep function analysis (when enabled) uses `token_get_all()` under a size cap instead of substring matching, to resist obfuscation and to avoid false positives on prose/code in other languages (the function layer only triggers inside an actual PHP open-tag region).
- Alternative considered: head-only scan. Rejected — polyglot payloads sit far past byte 16.

### D3 — SVG: sanitize, don't detect
Replace the SVG regex scanner with an allowlist sanitizer (adopt `enshrined/svg-sanitizer`, MIT, or an equivalent vetted library) that parses the SVG, drops disallowed elements/attributes/URL schemes and all DTD/entities, and emits a cleaned document. The cleaned bytes are what the application stores. Where the package itself parses XML, it installs `libxml_set_external_entity_loader(fn() => null)`, parses with `LIBXML_NONET` and without `LIBXML_NOENT`, and (PHP < 8) calls `libxml_disable_entity_loader(true)`.
- Alternative considered: harden the regex. Rejected — unquoted handlers, encodings, and namespaces make blocklist regex unwinnable; detection-only also leaves a stored-XSS file on disk.

### D4 — PDF: decode before scanning, via a real parser
Adopt `smalot/pdfparser` (or equivalent) to inflate `FlateDecode`/`LZW`/`ASCII85`/`ASCIIHex` streams, parse object streams (`/ObjStm`), decode `#xx` name escapes, and resolve indirect references before matching `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`. Encrypted PDFs are decrypted with the empty/owner password when possible, else quarantined/rejected. Page count is read from the catalog page tree `/Count`. Name matches are anchored on PDF delimiters to avoid false positives.
- Alternative considered: write a minimal inflater inline. Acceptable fallback if a dependency is undesirable, but a maintained parser is preferred for correctness and ObjStm handling.

### D5 — Archives: stream-decompress with a hard cap; never trust headers
Zip-bomb and size limits are enforced by streaming each entry through a bounded reader and counting **actual** decompressed bytes against a global cap; declared (central-directory) sizes are only used to flag declared-vs-actual mismatches. Every dotted segment of each entry name is checked; names are normalized for trailing whitespace/dots/control chars and NTFS ADS (`:`); both `/` and `\` traversal and absolute paths are detected; symlink/hardlink entries (zip external attrs / tar typeflag) are rejected. Nested archives are recursed within a depth cap. The blocklist is completed (`.pht`, `.phtml`, `.shtml`, `.htaccess`, `.inc`, `web.config`, …). Unsupported-but-detected formats (ISO/CAB/encrypted) are rejected, not silently passed.

### D6 — Office: cover OLE + case-insensitive OPC + relationships
Detect macros/OLE/ActiveX in both OOXML (zip) and legacy OLE/CFB (`D0CF11E0`). Look up package parts case-insensitively (`ZipArchive::FL_NOCASE` / `strcasecmp`) and resolve VBA/OLE/ActiveX via `.rels` relationship types and `[Content_Types].xml`, not filename patterns. Fail closed when `blockMacros` is on and a container cannot be fully parsed. `loadConfiguration()` must not overwrite explicitly-set fluent flags.

### D7 — Images: guard before decode; prefer re-encode
Read dimensions/byte size from the header and reject images exceeding a configurable pixel/byte cap **before** any `imagecreatefrom*`. Scan all EXIF/IFD sections and the `COMMENT` array (not a 13-tag allowlist) and run the full PHP byte-scanner on image content (independent of `ext-exif`). Provide an optional, recommended `reencode` mode (GD/Imagick) that rewrites the image to a clean file, destroying appended/segment payloads; stripping either supports all advertised formats or fails loudly.

### D8 — MIME detection: structural, disambiguated, memoized, fail-closed
Read a configurable header window (default ≥ 512 bytes, more when needed) and classify by structure. Disambiguate OLE compound subtypes (doc/xls/ppt/msg), `ftyp` brands (mp4/mov/m4a/heic/avif), RIFF (webp/avi/wav), and ZIP families (office/jar/apk/epub/odf). Validate short signatures structurally (e.g., BMP: size at offset 2, DIB header at offset 14). Memoize `detect()` per file. Unknown → `null`, which the orchestrator treats as untrusted (scan as text, block dangerous routing), never as "binary safe". Fix the duplicate signature key.

### D9 — Orchestration: one pass, config-driven, fail-closed
`Safeguard` reads the file once, builds a shared content/handle, and routes to sub-scanners by **content-derived type** (case-insensitive extension only as a secondary signal). Archive and Office scanning are enabled from config by default. A configurable `max_scan_size` bounds work; oversize uploads are rejected (or routed to a header-only policy) rather than scanned unbounded. All scanner `config()/logger()/request()` access is guarded so validation works in queue/CLI/non-HTTP contexts.

### D10 — Multi-version Laravel/PHP strategy
Single codebase targeting `illuminate/support|validation|http ^10|^11|^12` and `php ^8.1`. Use only APIs stable across 10–12 (`ValidationRule` contract is available in 10.x; keep the closure-extension registrations working on all three). CI runs a matrix: PHP {8.1, 8.2, 8.3, 8.4} × Laravel {10, 11, 12} via `orchestra/testbench` {8, 9, 10}, excluding unsupported PHP/Laravel pairs. `composer.json` declares all hard extensions; optional ones are `class_exists`/`function_exists` guarded.

### D11 — Performance model
Target: a single header read for type detection plus at most one full-content pass for code scanning, with format-specific scanners operating on already-decoded structures rather than re-reading the file. Hard `max_scan_size` cap (default e.g. 25 MB, configurable) beyond which the file is rejected or only header-validated. Replace `preg_match_all` with `preg_match` where a boolean suffices; validate user regex at config load (drop `@`-suppression). A `tests/Performance` benchmark asserts bounded time/memory for representative and adversarial inputs.

### D12 — Library dependencies are pinned and matrix-verified
Adopt `smalot/pdfparser` and `enshrined/svg-sanitizer` with pinned minimum versions in `composer.json`; regenerate `composer.lock`; add both to the CI matrix install step so any PHP 8.1–8.4 / Laravel 10–12 conflict surfaces in CI. Keep the inline PDF-inflater fallback (D4) behind a `class_exists` guard so the package degrades to in-house decoding if the parser is unavailable.

### D13 — DoS guard: rate/size limiting
In addition to `max_scan_size`, enforce configurable upload-rate limits (max file size, files-per-minute, total-bytes-per-minute) so expensive scanning cannot be weaponized. Limits fail closed (reject over-limit) and are guarded for non-HTTP contexts (no request → skip request-keyed limits, still enforce size).

### D14 — Optional quarantine of rejected files
Provide an opt-in quarantine: when enabled, a rejected file is copied to a configured path with a sanitized JSON metadata sidecar (original name stripped of control chars, detected type, threats, timestamp). Disabled by default; retention is config-driven (no Artisan dependency). Quarantine writes are wrapped so a failure never breaks validation or causes fail-open (same crash-safety as logging).

### D15 — Static analysis gate
Add `phpstan.neon` (start at an achievable level, ratchet up) over `src/` and run it in CI as a release gate alongside phpunit/coverage/`composer validate --strict`.

## Risks / Trade-offs

- **New dependencies** (`enshrined/svg-sanitizer`, `smalot/pdfparser`) increase surface and must themselves be kept patched → pin minimums, watch advisories, keep an inline fallback path for PDF if the dependency is rejected.
- **Stricter behavior breaks existing callers** → semver-major + `UPGRADE.md` + config switches to soften where safe (e.g., availability-only checks log instead of hard-fail on indeterminate input).
- **Re-encoding images changes bytes/quality** → opt-in (recommended) with documented quality settings; never silently lossy without config.
- **Decode-before-scan costs CPU** → bounded by `max_scan_size` and single-pass design; benchmarked.
- **Multi-version matrix maintenance** → encoded in CI so regressions are caught automatically.

## Migration Plan

1. Land detection/orchestration fixes behind fail-closed defaults; keep public API (rule names, fluent methods) stable.
2. Add new config keys with safe defaults; map/deprecate dead keys (read old keys for one minor with a deprecation log, then remove).
3. Ship `UPGRADE.md` enumerating behavior changes and config migration; cut the first stable tag `1.0.0` (no prior stable tag exists — the package was only installable at `minimum-stability=dev`).
4. Rebuild README/docs/config comments to match behavior; add `SECURITY.md`.
5. Add `.gitattributes export-ignore`; remove dev artifacts; drop `minimum-stability=dev`.
6. Green the CI matrix and coverage floor; tag the release.
Rollback: pin to a pre-1.0 dev commit; the change is additive at the API level, so downgrade is a composer constraint change.

## Open Questions

- Adopt external parser dependencies (`smalot/pdfparser`, `enshrined/svg-sanitizer`) or implement minimal in-house equivalents? (Default decision: adopt vetted libraries; revisit if dependency budget is a hard constraint.)
- Should image re-encoding be the default `safeguard` behavior or opt-in? (Default decision: opt-in but recommended in docs; revisit after benchmarking.)
- Default `max_scan_size` value and the over-cap policy (reject vs header-only). (Default decision: reject over-cap with a clear message; configurable.)

## Resolved Decisions

- **Version:** This is the first stable release `1.0.0`, not a major bump from a prior tag (none exists).
- **Scope:** 1.0.0 = hardening + static analysis (PHPStan) + DoS rate/size limiting + opt-in quarantine. Events/hooks, media scanning, WebAssembly, custom-exception hierarchy, and ServiceProvider de-dup are deferred (see proposal "Out of Scope").
- **Spec hygiene:** `add-security-enhancements` is archived with `--skip-specs` (its capabilities are superseded by this change's specs) to avoid duplicate capability trees in `specs/`.
