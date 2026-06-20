# Upgrade Guide

## Upgrading to 1.0.0 (from a pre-1.0 `dev` install)

`1.0.0` is the first **stable** release. Earlier code was only installable at
`minimum-stability=dev`, so there is no prior tagged version to upgrade *from* in
the semver sense — this guide targets users who were tracking the dev branch.

Update your constraint:

```jsonc
// composer.json
"abdian/laravel-upload-guard": "^1.0"
```

and remove any `"minimum-stability": "dev"` you added solely for this package.
Then republish the config to pick up the new keys:

```bash
php artisan vendor:publish --tag=safeguard-config --force
```

### New required PHP extensions

The package now declares `ext-fileinfo`, `ext-zip`, `ext-dom`, `ext-libxml`, and
`ext-exif`. Composer will refuse to install without them. `ext-gd` (or
`ext-imagick`) is only needed for the optional image **re-encode** mode and is
guarded at runtime. New library dependencies `smalot/pdfparser` and
`enshrined/svg-sanitize` are installed automatically.

## Behavior changes (stricter, fail-closed)

The package now **rejects files the pre-1.0 code accepted**, and may **rewrite**
some accepted files. Expect the following to now be rejected:

- **Polyglots** — a valid image/PDF/ZIP header followed by `<?php`/`<?=`/`<?`
  (these were previously skipped as "binary safe").
- **Files of unknown type** carrying a script opener (`application/octet-stream`
  is no longer auto-allowed).
- **Compressed/encrypted PDFs with active content** — `/JavaScript`, `/JS`,
  `/OpenAction`, `/AA` inside Flate/ObjStm streams or hex-escaped names; encrypted
  PDFs that cannot be inspected.
- **Zip bombs** including forged central-directory sizes, plus archive entries
  with path traversal, NTFS ADS, dangerous extensions on any segment, symlinks,
  and unsupported/encrypted archive formats.
- **Legacy-macro Office docs** (`.doc/.xls/.ppt`) and case-variant OOXML macros.
- **DTD-bearing or scripted SVGs** — by default these are **sanitized in place**
  (the stored SVG is the cleaned version); set `svg_scanning.mode = 'reject'` to
  refuse them instead.
- **Decompression-bomb images** (rejected from the header before any decode).

Conversely, several **false positives are fixed** — these now pass:

- real `.xls`/`.ppt` (OLE subtype disambiguation), `.js`/`.csv`/`.py`/`.md` text
  files that merely mention `eval`/`system`, and compressed PDFs (correct page
  counts).

The all-in-one `safeguard` rule now performs **archive and Office scanning by
default** — you no longer need `->scanArchives()` or `->blockMacros()`.

## Configuration migration

| Old key | Status in 1.0.0 |
| --- | --- |
| `archive_scanning.max_compression_ratio` | **Removed.** Superseded by `archive_scanning.max_decompressed_size` (a hard cap on *actual* streamed bytes). |
| `archive_scanning.rar_fail_open` | **Removed.** RAR/7z/ISO/CAB cannot be stream-inspected and are now rejected (fail-closed). |
| `svg_scanning.custom_dangerous_tags` / `exclude_tags` / `custom_dangerous_attributes` / `exclude_attributes` | **Removed.** Sanitization is allowlist-based; use `svg_scanning.allowed_tags` / `allowed_attributes` to customize. |
| `image_scanning.suspicious_exif_tags` | **Removed.** All EXIF/IFD sections and `COMMENT` are scanned. |

### New keys

- `max_scan_size`, `over_cap_policy`, `header_window`
- `svg_scanning.mode`, `svg_scanning.remove_remote_references`, `svg_scanning.allowed_tags`, `svg_scanning.allowed_attributes`
- `pdf_scanning.encrypted_policy`
- `archive_scanning.max_decompressed_size`, `archive_scanning.blocked_filenames`
- `image_scanning.max_pixels`, `image_scanning.max_bytes`, `image_scanning.reencode`, `image_scanning.reencode_quality`
- `rate_limiting.*` (DoS guard, off by default)
- `quarantine.*` (opt-in, off by default)

## TOCTOU note

Scanning the PHP temp file does not by itself close the temp→storage window. Use
`validateDestinationPath()` immediately before moving a validated upload, and
prefer enabling `image_scanning.reencode` for image uploads.
