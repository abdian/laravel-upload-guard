# What is Laravel Safeguard?

Laravel Safeguard is a security package for Laravel that protects your application from malicious file uploads.

## Why Do You Need It?

Traditional Laravel file validation only checks extensions and client-provided MIME types - **both can be easily faked**.

```php
// Traditional validation - NOT SECURE
$request->validate([
    'file' => 'required|mimes:jpg,png,pdf'
]);
```

**Problems:**
- ❌ Only checks file extension
- ❌ Trusts client-provided MIME type
- ❌ Doesn't detect PHP code in images
- ❌ Doesn't scan for XSS in SVG
- ❌ Doesn't check PDF for malware

## How Safeguard Solves This

```php
// Laravel Safeguard - SECURE
$request->validate([
    'file' => 'required|safeguard'
]);
```

**Protection:**
- ✅ Reads magic bytes to detect real file type
- ✅ Scans for 40+ dangerous PHP functions
- ✅ Detects XSS vulnerabilities in SVG
- ✅ Analyzes image EXIF metadata
- ✅ Scans PDFs for JavaScript
- ✅ Blocks executables automatically

## Key Features

### Magic Bytes Detection
Validates real MIME type by reading file signatures - supports 70+ formats.

### PHP Code Scanning
Scans files for dangerous functions like `eval()`, `exec()`, `system()`.

### Image Security
Analyzes EXIF metadata, detects GPS location, can strip metadata.

### PDF Protection
Scans PDFs for JavaScript and validates page count.

## Supported Versions

- Laravel 13.x ✅
- Laravel 12.x ✅
- Laravel 11.x ✅
- Laravel 10.x ✅
- PHP 8.1+ required (Laravel 13.x requires PHP 8.3+)

## Next Steps

- [Installation](/guide/installation) - Get started in 5 minutes
- [Quick Start](/guide/quick-start) - Basic usage examples
- [Validation Rules](/guide/rules) - See all available rules
