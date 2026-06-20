# Laravel Safeguard Package

## Overview

**Package Name:** `abdian/laravel-upload-guard`
**Type:** Laravel File Upload Security Validator
**PHP Version:** 8.1+
**Laravel Versions:** 10.x, 11.x, 12.x, 13.x
**License:** MIT

### Purpose

Secure, **fail-closed** file upload validation that protects Laravel applications
from malicious file uploads using:
- Structural content-type detection (≥512-byte header window, fail-closed `null`)
- Always-on PHP/script code scanning (no binary-skip early-exit)
- SVG allowlist sanitization, PDF decode-before-scan, streaming archive
  zip-bomb detection, OLE + OOXML Office macro detection, and an image
  decompression-bomb guard
- An optional DoS rate guard and opt-in quarantine

### 1.0.0 Architecture (fail-closed)

Every ambiguous outcome (unknown MIME, unparsable container, scanner exception)
resolves to **reject** for security checks. Detection is structural, not
substring-over-raw-bytes; there is no `binary → trust` early-exit and
`application/octet-stream` is never treated as "safe". The all-in-one `safeguard`
rule runs a single-pass pipeline with archive **and** Office scanning enabled by
default. New runtime dependencies: `smalot/pdfparser`, `enshrined/svg-sanitize`.

---

## Directory Structure

```
src/
├── config/
│   └── safeguard.php                    # Configuration file
├── Rules/
│   ├── Safeguard.php                    # Main comprehensive rule
│   ├── SafeguardMime.php                # MIME type validation
│   ├── SafeguardPhp.php                 # PHP code scanning
│   ├── SafeguardSvg.php                 # SVG/XSS detection
│   ├── SafeguardImage.php               # Image metadata scanning
│   ├── SafeguardPdf.php                 # PDF security scanning
│   ├── SafeguardDimensions.php          # Image dimension validation
│   └── SafeguardPages.php               # PDF page count validation
├── MimeTypeDetector.php                 # Magic bytes detection
├── PhpCodeScanner.php                   # PHP threat detection
├── SvgScanner.php                       # SVG threat detection
├── ImageScanner.php                     # Image threat detection
├── PdfScanner.php                       # PDF threat detection
├── ExtensionMimeMap.php                 # File extension-MIME mapping
├── SecurityLogger.php                   # Security event logging
└── SafeguardServiceProvider.php         # Laravel service provider

tests/
└── MimeTypeDetectorTest.php             # Unit tests

docs/                                     # VitePress documentation
├── .vitepress/
│   ├── config.mjs                       # VitePress configuration
│   └── theme/                           # Custom theme
├── guide/
│   ├── index.md                         # Introduction
│   ├── installation.md                  # Installation guide
│   ├── quick-start.md                   # Quick start guide
│   ├── usage.md                         # Basic usage
│   ├── rules.md                         # Validation rules
│   └── config.md                        # Configuration
├── api/
│   ├── index.md                         # API reference - Rules
│   └── config.md                        # API reference - Config
└── index.md                             # Documentation homepage
```

**Namespace:** `Abdian\UploadGuard\`

**Documentation URL:** https://abdian.github.io/laravel-upload-guard/

---

## Core Classes

All scanner classes are located directly in `src/` (not in a subfolder).

### SafeguardServiceProvider.php (`src/SafeguardServiceProvider.php`)

- Registers all validation rules with Laravel's validator
- Publishes configuration file
- Automatically integrates with Laravel's native `mimes` rule
- Extracts MIME types from validator rules and enforces strict matching

### ExtensionMimeMap.php (`src/ExtensionMimeMap.php`)

- Maps file extensions to their valid MIME types (supports 70+ formats)
- Provides strict extension-to-MIME matching to prevent spoofing
- Supports all common file types (images, documents, audio, video, archives, fonts)

**Methods:**
- `getMimeTypes()` - Get MIME types for an extension
- `getExtensions()` - Get extensions for a MIME type
- `isValidExtensionForMime()` - Check if extension is valid for MIME
- `extensionsToMimeTypes()` - Convert extensions array to MIME types

### MimeTypeDetector.php (`src/MimeTypeDetector.php`)

- Detects the real type from byte structure over a configurable header window
  (default ≥512 bytes), memoized per file
- Disambiguates container families: OLE compound subtypes (doc/xls/ppt/msg via
  `Support\CompoundFile`), ftyp brands, RIFF, ZIP families (office/jar/apk/epub/odf)
- Structurally validates short signatures (e.g. BMP size@2, DIB@14)
- Returns `null` for unknown content; callers treat `null` as **untrusted**
  (never "binary safe"). `application/octet-stream` maps to `null`.

**Methods:**
- `detect()` - Detect MIME type (or `null`)
- `isDangerous()` - Check if a type is configured dangerous (incl. JAR/APK)
- `flushCache()` - Clear the per-file detection memo

> The legacy `isBinaryFile()` early-exit that skipped scanning for binaries was
> removed as a security gate; code scanning now runs on every upload.

---

## Validation Rules

### 7 Main Rules

| Rule | Description |
|------|-------------|
| `Safeguard` | Main comprehensive rule - orchestrates all security checks |
| `SafeguardMime` | MIME type validation with fake extension detection |
| `SafeguardPhp` | PHP code scanning for malicious patterns |
| `SafeguardSvg` | SVG/XSS detection |
| `SafeguardImage` | Image metadata and EXIF scanning |
| `SafeguardPdf` | PDF security scanning |
| `SafeguardDimensions` | Image dimension validation |
| `SafeguardPages` | PDF page count validation |

### String Rules

Used as `'field' => 'required|rule'`:

```php
'file' => 'required|safeguard'
'file' => 'required|safeguard_mime:image/jpeg,image/png'
'file' => 'required|safeguard_php'
'file' => 'required|safeguard_image'
'file' => 'required|safeguard_pdf'
'file' => 'required|safeguard_svg'
'file' => 'required|safeguard_dimensions:1024,1024,100,100'
'file' => 'required|safeguard_pages:1,50'
```

### Fluent API

Used as `new Safeguard()->method()`:

#### Type Filters
- `imagesOnly()` - Allow only images
- `pdfsOnly()` - Allow only PDFs
- `documentsOnly()` - Allow common document formats

#### MIME Control
- `allowedMimes(array)` - Set allowed MIME types
- `strictExtensionMatching(bool)` - Enforce extension-MIME matching

#### Image Control
- `maxDimensions(width, height)`
- `minDimensions(width, height)`
- `dimensions(minW, minH, maxW, maxH)`
- `blockGps()`
- `stripMetadata()`

#### PDF Control
- `maxPages(count)`
- `minPages(count)`
- `pages(min, max)`
- `blockJavaScript()`
- `blockExternalLinks()`

---

## Scanner Classes

All scanner classes are in `src/` namespace `Abdian\UploadGuard\`.

### PhpCodeScanner.php (`src/PhpCodeScanner.php`)

- 30+ dangerous PHP functions detection
- Suspicious pattern matching
- Web shell pattern recognition
- Configuration-based customization
- Skips binary files automatically

**Detected Patterns:**
- PHP tags: `<?php`, `<?=`, `<?`
- Functions: `eval`, `exec`, `system`, `shell_exec`, `base64_decode`, etc.
- Web shells: C99, R57, B374K, WSO, etc.
- Dangerous combinations: `eval(base64_decode())`, `assert(gzinflate())`

### SvgScanner.php (`src/SvgScanner.php`)

- Detects dangerous SVG tags: `script`, `iframe`, `embed`, `object`, `use`, `foreignObject`, `animate`
- 21+ event handlers: `onload`, `onclick`, `onerror`, etc.
- Dangerous protocols: `javascript:`, `data:text/html`, `vbscript:`
- Obfuscation detection: base64, URL encoding, HTML entities, CDATA

### ImageScanner.php (`src/ImageScanner.php`)

- PHP code detection in binary content
- Trailing bytes scanning (hidden code after image end markers)
- EXIF metadata scanning
- GPS data detection
- Metadata stripping using GD library
- Supports JPEG, PNG, GIF

### PdfScanner.php (`src/PdfScanner.php`)

- Dangerous PDF actions: `/Launch`, `/JavaScript`, `/SubmitForm`, `/GoToR`, `/EmbeddedFile`
- JavaScript detection with suspicious function patterns
- Suspicious URL protocol detection
- Obfuscation detection: FlateDecode compression, hex-encoded strings, encryption layers
- Embedded file detection
- Metadata extraction

---

## Configuration

**File:** `src/config/safeguard.php`

### Sections

#### 1. MIME Type Validation
```php
'mime_validation' => [
    'strict_check' => true,           // Fail if detected MIME doesn't match client-provided
    'block_dangerous' => true,         // Auto-block executables and scripts
    'custom_signatures' => [],         // Custom magic byte signatures
    'dangerous_types' => [...]         // 19 dangerous MIME types listed
]
```

#### 2. PHP Code Scanning
```php
'php_scanning' => [
    'enabled' => true,
    'mode' => 'default',               // 'default', 'strict', or 'custom'
    'scan_functions' => [],            // Custom functions to scan
    'custom_dangerous_functions' => [],
    'exclude_functions' => [],
    'custom_patterns' => [],
    'exclude_patterns' => []
]
```

#### 3. SVG Security Scanning
```php
'svg_scanning' => [
    'enabled' => true,
    'custom_dangerous_tags' => [],
    'exclude_tags' => [],
    'custom_dangerous_attributes' => [],
    'exclude_attributes' => []
]
```

#### 4. Image Security Scanning
```php
'image_scanning' => [
    'enabled' => true,
    'check_gps' => true,
    'block_gps' => false,
    'auto_strip_metadata' => false,
    'suspicious_exif_tags' => [...]    // 6 EXIF tags monitored
]
```

#### 5. PDF Security Scanning
```php
'pdf_scanning' => [
    'enabled' => true,
    'custom_dangerous_actions' => [],
    'exclude_actions' => []
]
```

#### 6. Logging & Reporting
```php
'logging' => [
    'enabled' => true,
    'channel' => null,                 // Laravel log channel
    'detailed' => true,
    'hash_algorithm' => 'sha256'       // 'md5', 'sha256', or false
]
```

---

## SecurityLogger

Centralized security event logging with:

### Event Types
1. `MIME_MISMATCH`
2. `DANGEROUS_FILE`
3. `PHP_CODE`
4. `SVG_XSS`
5. `IMAGE_THREAT`
6. `PDF_THREAT`
7. `GPS_DETECTED`
8. `DIMENSION_EXCEEDED`

### Threat Levels
- `low`
- `medium`
- `high`
- `critical`

### Logged Information
- File hash (MD5/SHA256)
- User ID
- IP address
- Event type
- Threat level
- Detailed context

---

## How It Works

### Workflow

1. **Registration Phase** (SafeguardServiceProvider)
    - Loads configuration
    - Registers 8 validation rules with Laravel's validator
    - Hooks into `Validator::extend()` for each rule

2. **Integration with Laravel's `mimes` Rule**
    - Detects if `mimes:jpg,png,pdf` rule exists
    - Extracts extensions and converts to MIME types
    - Enables automatic strict extension matching

3. **Detection Process**

```
File Upload
    ↓
Magic Bytes Detection (MimeTypeDetector)
    ↓
Is Allowed MIME Type? (SafeguardMime)
    ↓
PHP Code Scanning (PhpCodeScanner)
    ↓
File-Type-Specific Scanning:
  - SVG: SvgScanner (check XSS vectors)
  - Images: ImageScanner (check EXIF/metadata)
  - PDF: PdfScanner (check JavaScript)
    ↓
Dimension/Page Count Validation
    ↓
Result: Pass/Fail with Threat Report
```

4. **Security Logging**
    - Logs all threats using SecurityLogger
    - Includes file hash, user ID, IP address
    - Stores event type, threat level, detailed context

---

## Usage Examples

### Basic Usage
```php
// All security checks
'file' => 'required|safeguard'
```

### Images with Constraints
```php
'avatar' => ['required', (new Safeguard())
    ->imagesOnly()
    ->maxDimensions(1024, 1024)
    ->blockGps()
]
```

### PDFs with Restrictions
```php
'document' => ['required', (new Safeguard())
    ->pdfsOnly()
    ->maxPages(50)
    ->blockJavaScript()
]
```

### Individual Rules
```php
'avatar' => 'required|safeguard_mime:image/jpeg,image/png|safeguard_image'
```

### With Laravel's mimes Rule
```php
'file' => 'required|mimes:jpg,png,pdf|safeguard'
```

---

## Tests

**File:** `tests/MimeTypeDetectorTest.php`

### Test Cases (25 tests)

| Test | Description |
|------|-------------|
| `test_detects_jpeg_files()` | JPEG detection via magic bytes |
| `test_detects_png_files()` | PNG detection |
| `test_detects_gif_files()` | GIF detection |
| `test_detects_pdf_files()` | PDF detection |
| `test_detects_zip_files()` | ZIP detection |
| `test_detects_php_files()` | PHP file detection |
| `test_detects_windows_executables()` | Windows EXE detection |
| `test_detects_shell_scripts()` | Shell script detection |
| `test_identifies_dangerous_files()` | Dangerous type identification |
| `test_returns_null_for_non_existent_file()` | Error handling |
| `test_identifies_images_as_binary_files()` | Binary file detection |
| `test_identifies_pdfs_as_binary_files()` | PDF as binary |
| `test_identifies_media_files_as_binary()` | Audio/video as binary |
| `test_php_files_not_binary()` | PHP correctly identified as text |
| `test_text_files_not_binary()` | Text file handling |

**Testing Framework:** PHPUnit 10.0+

---

## Supported File Formats

### Images
JPEG, PNG, GIF, WebP, BMP, TIFF, ICO, SVG, HEIC

### Documents
PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, ODT, ODS, ODP, RTF, TXT

### Archives
ZIP, RAR, 7Z, TAR, GZIP, TAR.GZ

### Audio
MP3, WAV, OGG, M4A, FLAC, AAC

### Video
MP4, WebM, AVI, MOV, MKV, FLV

### Fonts
TTF, OTF, WOFF, WOFF2

### Others
JSON, XML, CSV, HTML, CSS, JavaScript

---

## Security Features Summary

| Feature | Description |
|---------|-------------|
| Magic Bytes Detection | Real MIME type validation (70+ formats) |
| PHP Code Scanning | Detects web shells and backdoors |
| XSS Protection | SVG and image EXIF scanning |
| PDF Security | JavaScript and dangerous action detection |
| Image Protection | EXIF metadata and GPS detection |
| Flexible Configuration | Fully customizable via config file |
| Fluent API | Elegant, chainable method calls |
| Security Logging | Detailed threat monitoring with forensics |
| Laravel Integration | Works seamlessly with native rules |

---

## Dependencies

- PHP >= 8.1
- Laravel >= 10.0
- GD Extension (for image processing)
- Fileinfo Extension (for MIME detection)

---

## Installation

```bash
composer require abdian/laravel-upload-guard
```

### Publish Configuration

```bash
php artisan vendor:publish --tag=safeguard-config
```

---

## Testing

**Framework:** PHPUnit 10.0+

### Running Tests

```bash
# Run all tests
./vendor/bin/phpunit

# Run with coverage report
./vendor/bin/phpunit --coverage-html coverage
```

**Configuration:** `phpunit.xml`

---

## Code Conventions

### PHP Standards
- **PHP Version:** 8.1+ (uses typed properties, constructor promotion, match expressions)
- **PSR-4 Autoloading:** `Abdian\UploadGuard\` maps to `src/`
- **Strict Types:** Not enforced project-wide, but recommended for new code

### Class Organization
- **Rules** (`src/Rules/`): Laravel validation rules implementing `ValidationRule` interface
- **Scanners** (`src/`): Threat detection classes with `scan()` methods returning arrays of findings
- **Support Classes** (`src/`): `ExtensionMimeMap`, `SecurityLogger`, `MimeTypeDetector`

### Naming Conventions
- **Rules:** `Safeguard{Type}.php` (e.g., `SafeguardMime.php`, `SafeguardPdf.php`)
- **Scanners:** `{Type}Scanner.php` (e.g., `PhpCodeScanner.php`, `SvgScanner.php`)
- **String Rules:** `safeguard_{type}` (e.g., `safeguard_mime`, `safeguard_pdf`)

### Method Patterns
- Scanner classes use `scan(string $filePath): array` returning threat details
- Rule classes implement `validate(string $attribute, mixed $value, Closure $fail): void`
- Fluent API methods return `$this` for chaining

### Configuration
- All config in `src/config/safeguard.php`
- Published to `config/safeguard.php` in host application
- Access via `config('safeguard.key')` pattern

---

## Recent Changes

| Commit | Description |
|--------|-------------|
| 297d285 | Add strict extension-MIME matching and mapping |
| bc96039 | Fixed Bugs |
| e526df8 | Add VitePress documentation |
| d41ac1a | Fix critical array_merge bug breaking MIME type detection |
| 82f7d7f | Fix safeguard rule rejecting all files when MIME types not specified |

---

## Repository Links

- **GitHub:** https://github.com/abdian/laravel-upload-guard
- **Packagist:** https://packagist.org/packages/abdian/laravel-upload-guard
- **Documentation:** https://abdian.github.io/laravel-upload-guard/
