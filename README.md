<div align="center">

# 🛡️ Laravel Upload Guard

**Fail-closed file-upload validation for Laravel.**

A defense-in-depth layer that detects and blocks common malicious uploads —
polyglot web shells, malicious PDFs & SVGs, zip bombs, Office macros, and spoofed
MIME types — using structural parsing and content sanitization, not just regex.

*Not an antivirus, and not a sole security boundary — see [Limitations](#limitations--not-a-security-boundary).*

[![Latest Version](https://img.shields.io/packagist/v/abdian/laravel-upload-guard.svg?style=flat-square)](https://packagist.org/packages/abdian/laravel-upload-guard)
[![Total Downloads](https://img.shields.io/packagist/dt/abdian/laravel-upload-guard.svg?style=flat-square)](https://packagist.org/packages/abdian/laravel-upload-guard)
[![Tests](https://img.shields.io/github/actions/workflow/status/abdian/laravel-upload-guard/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/abdian/laravel-upload-guard/actions/workflows/tests.yml)
[![PHP Version](https://img.shields.io/packagist/php-v/abdian/laravel-upload-guard.svg?style=flat-square)](https://packagist.org/packages/abdian/laravel-upload-guard)
[![License](https://img.shields.io/packagist/l/abdian/laravel-upload-guard.svg?style=flat-square)](LICENSE)

</div>

```php
// One rule. Fail-closed by default.
$request->validate([
    'file' => 'required|safeguard',
]);
```

---

## Why?

Laravel's built-in `mimes` / `mimetypes` rules trust the **client-declared** type
and a coarse extension map. An attacker can upload `shell.php` renamed to
`avatar.jpg`, a real JPEG with PHP appended after the image data (a *polyglot*
web shell), an SVG carrying `<script>`, a PDF with an auto-run `/JavaScript`
action, or a 42 KB zip that expands to petabytes. None of those are caught by
extension checks.

**Upload Guard inspects the actual bytes** — magic structure, decoded PDF/zip
streams, sanitized SVG/Office internals — and **blocks anything it cannot prove
is safe**.

> ### 🔒 Design principle: *fail closed*
> When the package cannot be sure a file is safe, it **blocks** the upload.
> Unknown content types, unparsable containers, and scanner exceptions all
> resolve to **reject** — never to *allow*. Stricter than lax validators by design.
> It raises the bar a lot, but content scanning is best-effort — pair it with the
> operational [hardening steps](#limitations--not-a-security-boundary) below.

---

## Threat coverage

| Threat | How Upload Guard handles it |
|--------|------------------------------|
| 🐚 **Polyglot web shells** (PHP in JPEG / PDF / ZIP) | Always-on code scan on **every** upload, regardless of detected type |
| 🎭 **Spoofed MIME / double extension** | Structural byte detection + strict extension ↔ content matching |
| 🖼️ **Malicious SVG** (XSS / XXE) | Allowlist sanitization; DOCTYPE/entity/script stripping; **stored clean** |
| 📄 **Malicious PDF** (`/JavaScript`, `/OpenAction`, `/Launch`) | Decode-before-scan, indirect-`/Filter` resolution, bounded inflation |
| 💣 **Zip bombs & zip-slip** | **Global** actual-bytes cap across nested archives; traversal / symlink / NTFS-ADS rejection |
| 📎 **Office macros + macro-less RCE** | OOXML **and** legacy OLE/CFB; VBA, ActiveX, **DDE/DDEAUTO**, remote `attachedTemplate` |
| 🧨 **Image decompression bombs** | Header pixel/byte cap **before any decode**; optional re-encode to strip payloads |
| 🌊 **Upload DoS** | Hard size caps + optional per-IP rate limiting + opt-in forensic quarantine |

---

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [With Laravel's `mimes` rule](#with-laravels-mimes-rule)
  - [Fluent configuration](#fluent-configuration)
  - [Individual rules](#individual-rules)
- [Fluent API reference](#fluent-api-reference)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Limitations & not a security boundary](#limitations--not-a-security-boundary)
- [Testing](#testing)
- [Security](#security)
- [License](#license)

---

## Installation

```bash
composer require abdian/laravel-upload-guard
```

The service provider is auto-discovered. Publish the (fully commented) config to tune behavior:

```bash
php artisan vendor:publish --tag=safeguard-config
```

### Requirements

| | |
|---|---|
| **PHP** | 8.1 · 8.2 · 8.3 · 8.4 · 8.5 |
| **Laravel** | 10 · 11 · 12 · 13 |
| **Required extensions** | `fileinfo`, `zip`, `dom`, `libxml` |
| **Optional extensions** | `exif` (EXIF inspection/stripping) · `gd` *or* `imagick` (image re-encode mode) |

> Optional extensions degrade gracefully — the package installs and runs without them.

---

## Quick start

```php
public function store(\Illuminate\Http\Request $request)
{
    $request->validate([
        'file' => 'required|safeguard',
    ]);

    $request->file('file')->store('uploads');
}
```

The single `safeguard` rule runs — **by default, no fluent calls required**:

✅ structural MIME detection + dangerous-type blocking &nbsp;·&nbsp; ✅ strict
extension/content matching &nbsp;·&nbsp; ✅ always-on code scanning &nbsp;·&nbsp;
✅ SVG sanitization &nbsp;·&nbsp; ✅ image & PDF scanning &nbsp;·&nbsp; ✅ archive
**and** Office-macro scanning.

---

## Usage

### With Laravel's `mimes` rule

```php
$request->validate([
    'file' => 'required|safeguard|mimes:jpg,png,pdf',
]);
```

`safeguard` reads the allowed extensions and enforces that the file's **real**
content type matches them.

### Fluent configuration

```php
use Abdian\UploadGuard\Rules\Safeguard;

$request->validate([
    'avatar' => ['required', (new Safeguard)
        ->imagesOnly()
        ->maxDimensions(1920, 1080)
        ->blockGps()
        ->stripMetadata(),
    ],

    'document' => ['required', (new Safeguard)
        ->pdfsOnly()
        ->maxPages(50)
        ->blockJavaScript()
        ->blockExternalLinks(),
    ],

    'report' => ['required', (new Safeguard)
        ->documentsOnly(),   // archive + macro scanning are already on by default
    ],
]);
```

### Individual rules

Compose only the scanners you need:

```php
$request->validate([
    'avatar'   => 'required|safeguard_mime:image/jpeg,image/png|safeguard_image',
    'icon'     => 'required|safeguard_svg',
    'document' => 'required|safeguard_pdf|safeguard_pages:1,10',
    'photo'    => 'required|safeguard_dimensions:100,100,4000,4000',
    'archive'  => 'required|safeguard_archive',
    'report'   => 'required|safeguard_office',
]);
```

| Rule | Description |
|------|-------------|
| `safeguard` | All-in-one, fail-closed pipeline |
| `safeguard_mime:type1,type2` | Real content-type allowlist (+ dangerous-type block) |
| `safeguard_php` | Always-on PHP/script code scan |
| `safeguard_svg` | Allowlist SVG sanitization |
| `safeguard_image` | Image bomb / metadata / byte / trailing-data scan |
| `safeguard_pdf` | Decode-before-scan PDF analysis |
| `safeguard_archive` | Streaming archive inspection (zip/tar/gz) |
| `safeguard_office` | OOXML + legacy OLE macro / DDE / template detection |
| `safeguard_dimensions:maxW,maxH,minW,minH` | Image dimension limits |
| `safeguard_pages:min,max` | PDF page-count limits |

> **Note on `safeguard_archive` string params:** parameters are added to the
> **block** list (e.g. `safeguard_archive:iso,bin` also blocks `.iso`/`.bin`). To
> *allow* an otherwise-blocked extension, use the fluent rule:
> `(new SafeguardArchive)->allow(['sh'])`.

---

## Fluent API reference

All methods on `Abdian\UploadGuard\Rules\Safeguard` return `$this` (chainable).

| Method | Effect |
|--------|--------|
| `allowedMimes(array $mimes)` | Restrict to a real-content-type allowlist (`'image/*'` wildcards supported) |
| `imagesOnly()` / `pdfsOnly()` / `documentsOnly()` / `archivesOnly()` | Restrict to a file family |
| `maxDimensions(int $w, int $h)` / `minDimensions(int $w, int $h)` | Image dimension bounds |
| `dimensions(int $minW, int $minH, int $maxW, int $maxH)` | All four bounds at once |
| `maxPages(int)` / `minPages(int)` / `pages(int $min, int $max)` | PDF page-count bounds |
| `blockGps()` | Reject images that contain GPS/EXIF location data |
| `stripMetadata()` | Strip metadata from images |
| `blockJavaScript()` | Reject PDFs containing JavaScript |
| `blockExternalLinks()` | Reject PDFs containing external links |
| `strictExtensionMatching(bool = true)` | Force/disable extension ↔ content matching |
| `scanArchives(bool = true)` | Toggle archive scanning (on by default) |
| `blockMacros(bool = true)` / `allowMacros()` | Toggle Office-macro blocking (on by default) |

---

## Configuration

The published `config/safeguard.php` is fully commented; highlights:

```php
'max_scan_size'   => 25 * 1024 * 1024, // files larger than this are rejected
'over_cap_policy' => 'reject',         // or 'header_only'

'mime_validation' => [
    'strict_check'       => true,
    'block_dangerous'    => true,
    'block_undetectable' => false,     // set true to reject unknown content types
],

'archive_scanning' => [
    'enabled'               => true,                 // ON by default
    'max_decompressed_size' => 500 * 1024 * 1024,    // hard cap on ACTUAL bytes (global)
    'max_files_count'       => 10000,
    'max_nesting_depth'     => 3,
],

'office_scanning' => [
    'enabled'       => true,           // ON by default
    'block_macros'  => true,
    'block_activex' => true,
],

'svg_scanning'   => ['mode' => 'sanitize'],                 // or 'reject'
'image_scanning' => ['max_pixels' => 64_000_000, 'reencode' => false],

'rate_limiting'  => ['enabled' => false],  // DoS guard (opt-in)
'quarantine'     => ['enabled' => false],  // forensic quarantine (opt-in)
```

Every key is also overridable via environment variables (e.g.
`SAFEGUARD_ARCHIVE_SCAN`, `SAFEGUARD_SVG_MODE`, `SAFEGUARD_IMAGE_REENCODE`).

---

## How it works

<details>
<summary><b>Always-on code scanning</b></summary>

Every upload is scanned for PHP/script openers (`<?php`, `<?=`, bare `<?`,
`<script language=php>`, `<%`, `__halt_compiler`) **regardless of detected type** —
a valid image/PDF/ZIP header never exempts a file, so polyglot web shells appended
after a magic header are caught. The dangerous-function layer only triggers inside
real PHP regions, so `.js`/`.py`/`.csv` text never false-positives.
</details>

<details>
<summary><b>Structural MIME detection</b></summary>

Classifies by byte structure (≥512-byte header window), disambiguates
OLE/ftyp/RIFF/ZIP families (real `.xls` → Excel, JAR/APK detected), validates short
signatures, and returns *untrusted* (`null`) for unknown content — never
"binary safe".
</details>

<details>
<summary><b>SVG sanitization</b></summary>

SVGs run through an allowlist sanitizer and the **cleaned output is stored**.
Unquoted handlers, encoded `javascript:` URIs, `<script>`, and all
DTD/DOCTYPE/entities are removed. XML parsing installs a denying external-entity
loader (XXE-safe).
</details>

<details>
<summary><b>PDF decode-before-scan</b></summary>

Flate/LZW/ASCII85/ASCIIHex and object streams are inflated (with bounded output)
and `#xx` names decoded before matching `/JavaScript`, `/JS`, `/OpenAction`,
`/AA`, `/Launch`, `/EmbeddedFile`. Indirect and decoy `/Filter` references are
resolved so compressed payloads can't hide. Matches are delimiter-anchored and
case-sensitive. Encrypted PDFs that can't be inspected are rejected.
</details>

<details>
<summary><b>Real zip-bomb detection</b></summary>

Archives are streamed against a hard cap on *actual* decompressed bytes that is
**global across the whole nested-archive tree** (nested fan-out can't multiply it);
forged central-directory / TAR sizes can't bypass it. Traversal (both separators),
absolute paths, NTFS ADS, dangerous extensions on any name segment, symlinks, and
unreadable entries are all rejected.
</details>

<details>
<summary><b>Office macros & macro-less vectors</b></summary>

VBA/OLE/ActiveX in both OOXML and legacy OLE/CFB (`.doc/.xls/.ppt`), resolved via
relationships and content types (case-insensitive). Also detects `DDE`/`DDEAUTO`
field codes and external/remote-template (`attachedTemplate`) injection. The CFB
reader follows the full DIFAT chain and fails closed on truncated containers.
</details>

<details>
<summary><b>Image hardening</b></summary>

Decompression-bomb guard enforced from the header **before any decode** (also
inside the re-encode path), full EXIF/metadata + byte scanning (works without
`ext-exif`), trailing-data detection, and an optional GD/Imagick re-encode that
strips appended payloads.
</details>

---

## Limitations & not a security boundary

Upload Guard is **defense-in-depth, not a guarantee.** It is a synchronous
validator — **not an antivirus** (no AV signatures, sandboxed detonation, or ML) —
and content scanning is inherently best-effort: a determined attacker may craft a
payload it does not recognize. **Never treat an accepted file as proof it is safe.**
Always also:

- **Store uploads outside the web root**, on non-executable storage; never serve
  them from a location the web server can execute (PHP/CGI/FPM).
- **Serve user files with `X-Content-Type-Options: nosniff` and
  `Content-Disposition: attachment`** (or from a separate origin/CDN) so a browser
  can't be tricked into running HTML/SVG/JS via content-type sniffing.
- **Extract archives with a traversal-safe extractor in a sandbox** — don't feed
  uploaded archives straight to `tar` / `PharData::extractTo()`.
- Close the **temp→storage TOCTOU** window (move the validated file immediately;
  prefer `image_scanning.reencode` for images).

### Known gaps (intentionally not fully covered)

- **Spreadsheet / CSV formula injection** (`=cmd|…`, `=HYPERLINK(…)`) — a
  consumer-side (Excel/LibreOffice) risk; CSV is treated as text by default so
  legitimate data isn't rejected. Neutralize formulas on export instead.
- **MHTML "web archive" documents** (an `.mht`/`.mhtml` page saved with a `.doc`
  name) are not deeply parsed for embedded active content.
- **CSS-only SVG tricks** beyond remote references (e.g. clickjacking overlays)
  and **content-sniffing polyglots** — mitigated operationally by the `nosniff` +
  attachment serving above.

This package was independently red-teamed with 70+ novel hand-crafted attacks
during development and hardened against every confirmed bypass; that process also
confirmed no scanner is complete. Treat it as one strong layer among several.

### Notes

- **SVG storage:** in `sanitize` mode the uploaded file is rewritten in place with
  the cleaned SVG, so `->store()` persists the safe version. Set
  `svg_scanning.mode = reject` to reject dirty SVGs outright.
- **Workers:** rate-limiter counters are atomic, the MIME cache is bounded, and
  per-instance rule overrides are restored after each validation — safe under
  Octane / queue workers.

---

## Testing

```bash
composer test      # PHPUnit (Testbench) — 183 tests with malicious fixtures
composer analyse   # PHPStan (level 5)
composer check     # validate + analyse + test
```

---

## Security

Please report vulnerabilities **privately** — see [SECURITY.md](SECURITY.md)
(email **esanjdev@gmail.com** or open a private GitHub Security Advisory). Please
do not open public issues for security reports.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Run
`composer check` before opening a PR.

## License

Open-sourced under the [MIT license](LICENSE).
