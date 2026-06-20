# Security Features

Comprehensive guide to Laravel Safeguard's security protections.

---

## Overview

Laravel Safeguard protects against multiple attack vectors:

| Attack | Protection | Severity |
|--------|------------|----------|
| File Type Spoofing | Magic bytes detection | High |
| PHP Code Injection | Pattern scanning | Critical |
| XSS via SVG | Tag/event detection | High |
| XXE Attacks | Entity blocking | Critical |
| Zip Bombs | Ratio analysis | High |
| Office Macros | VBA detection | High |
| TOCTOU Attacks | Symlink validation | High |
| Path Traversal | Archive path check | Critical |

---

## XXE Protection

### What is XXE?

XML External Entity (XXE) attacks exploit XML parsers that process external entity references. Attackers can:

- Read local files (`/etc/passwd`)
- Perform SSRF attacks
- Cause denial of service

### Attack Example

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

### How We Protect

Safeguard scans SVG/XML content **before** any parsing:

1. Detects `<!DOCTYPE` with entity declarations
2. Blocks `SYSTEM` and `PUBLIC` entity references
3. Detects parameter entities (`%`)
4. Blocks billion laughs attack patterns

```php
// Automatic protection with safeguard rule
'icon' => 'required|safeguard'

// Or explicit SVG scanning
'icon' => 'required|safeguard_svg'
```

### Detected Patterns

| Pattern | Description |
|---------|-------------|
| `<!ENTITY ... SYSTEM ...>` | External file/URL reference |
| `<!ENTITY ... PUBLIC ...>` | External DTD reference |
| `<!ENTITY % ...>` | Parameter entity |
| `<!DOCTYPE ... SYSTEM "http://...">` | External DTD |
| Recursive entities | Billion laughs attack |

---

## Archive Scanning

### Threats in Archives

Archives (ZIP, TAR, RAR) can contain:

- **Malicious executables** (.exe, .bat, .php)
- **Path traversal** (`../../../etc/passwd`)
- **Zip bombs** (1MB → 1PB)
- **Nested archives** (infinite expansion)

### Zip Bomb Detection

A zip bomb is a small archive that expands to enormous size:

| Archive | Compressed | Uncompressed |
|---------|------------|--------------|
| 42.zip | 42 KB | 4.5 PB |
| zbsm.zip | 42 KB | 5.5 GB |

Safeguard streams each entry through a bounded reader and counts the **actual**
decompressed bytes against `max_decompressed_size` (default 500 MB), aborting the
moment the cap is exceeded. It never trusts the central-directory sizes, so a
42.zip-class bomb that *declares* a tiny size cannot bypass it. Entry counts
(`max_files_count`) and nesting depth (`max_nesting_depth`) are bounded too, and
unsupported or encrypted entries are rejected rather than passed.

### Path Traversal Detection

Archives can contain files with malicious paths:

```
../../../etc/passwd
..\..\..\..\windows\system32\config\sam
/etc/shadow
C:\Windows\System32\config\SAM
```

All these patterns are detected and blocked.

### Usage

```php
// Enable archive scanning
'backup' => ['required', (new Safeguard())->scanArchives()]

// Dedicated rule
'archive' => 'required|safeguard_archive'

// String params are ADDED to the block list (e.g. also block .iso and .bin)
'archive' => 'safeguard_archive:iso,bin'

// To ALLOW an otherwise-blocked extension, use the fluent rule:
'archive' => ['required', (new \Abdian\UploadGuard\Rules\SafeguardArchive())->allow(['sh'])]
```

### Configuration

```php
'archive_scanning' => [
    'enabled' => true,                              // on by default
    'max_decompressed_size' => 500 * 1024 * 1024,  // hard cap on ACTUAL bytes
    'max_files_count' => 10000,
    'max_nesting_depth' => 3,
    'blocked_extensions' => ['php', 'phtml', 'exe', 'bat', 'sh', 'js'],
],
```

---

## Office Macro Detection

### The Threat

VBA macros in Office documents are a primary malware vector:

- Emotet, TrickBot, Dridex spread via macro documents
- Macros can execute arbitrary code
- Users often enable macros without understanding risks

### What We Detect

| Indicator | Location |
|-----------|----------|
| `vbaProject.bin` | `word/`, `xl/`, `ppt/` directories |
| Macro content types | `[Content_Types].xml` |
| ActiveX controls | `activeX/` directory |
| Extension spoofing | `.docm` renamed to `.docx` |

### Content Type Detection

Office Open XML declares content types in `[Content_Types].xml`:

```xml
<Types>
  <Override PartName="/word/vbaProject.bin"
    ContentType="application/vnd.ms-office.vbaProject"/>
</Types>
```

### Usage

```php
// Block macros
'document' => ['required', (new Safeguard())->blockMacros()]

// Dedicated rule
'report' => 'required|safeguard_office'

// Allow macros explicitly
'report' => 'safeguard_office:allow_macros'
```

### Configuration

```php
'office_scanning' => [
    'block_macros' => true,
    'block_activex' => true,
    'allowed_macro_extensions' => ['docm', 'xlsm', 'pptm'],
],
```

---

## Symlink Protection (TOCTOU)

### The Attack

TOCTOU (Time-of-Check-Time-of-Use) exploits race conditions:

```
1. User uploads safe.jpg (legitimate file)
2. Safeguard validates → passes
3. Attacker replaces safe.jpg with symlink to /etc/passwd
4. Application reads "safe.jpg" → reads /etc/passwd
```

### How We Protect

Before reading any file, Safeguard:

1. Checks if file is a symbolic link (`is_link()`)
2. Resolves real path (`realpath()`)
3. Validates path is in allowed directories

```php
// This is checked automatically in all scanners
if (is_link($path)) {
    return false; // Reject
}

$realPath = realpath($path);
if (!str_starts_with($realPath, $allowedDir)) {
    return false; // Reject
}
```

### Configuration

```php
'security' => [
    'check_symlinks' => true,
    'allowed_upload_paths' => null, // auto-detect
],
```

---

## PHP Code Detection

### Threats

PHP code can be hidden in:

- Image EXIF metadata
- SVG files
- PDF content
- Archive contents

### Detection Patterns

| Category | Examples |
|----------|----------|
| Tags | `<?php`, `<?=`, `<?` |
| Execution | `eval()`, `exec()`, `system()` |
| Obfuscation | `base64_decode()`, `gzinflate()` |
| Web shells | C99, R57, B374K patterns |

### Dangerous Combinations

```php
// These are always flagged
eval(base64_decode(...))
assert(gzinflate(...))
preg_replace('/e', ...)  // Deprecated /e modifier
```

---

## Image Security

### Threats in Images

- PHP code in EXIF Comment fields
- Trailing bytes after image end marker
- GPS location data (privacy risk)

### EXIF Scanning

```php
// Check these tags for malicious content
$suspiciousTags = [
    'Comment', 'UserComment', 'ImageDescription',
    'Artist', 'Copyright', 'Software',
];
```

### Trailing Bytes

Images have end markers:

| Format | End Marker |
|--------|------------|
| JPEG | `\xFF\xD9` |
| PNG | `IEND` chunk |
| GIF | `\x3B` |

Safeguard checks for suspicious content after these markers.

---

## PDF Security

### Threats in PDFs

- Embedded JavaScript
- Auto-execute actions
- External connections
- Embedded executables

### Detected Actions

| Action | Risk |
|--------|------|
| `/JavaScript` | Code execution |
| `/Launch` | Run external application |
| `/SubmitForm` | Send data externally |
| `/EmbeddedFile` | Hidden files |
| `/GoToR` | Remote destinations |

### Usage

```php
'document' => ['required', (new Safeguard())
    ->pdfsOnly()
    ->blockJavaScript()
    ->blockExternalLinks()
]
```

---

## Best Practices

### Recommended Configuration

```php
// Production settings
'archive_scanning' => [
    'enabled' => true,
    'max_decompressed_size' => 100 * 1024 * 1024, // Strict cap on actual bytes
    'max_files_count' => 1000,
],

'office_scanning' => [
    'block_macros' => true,
    'block_activex' => true,
],

'security' => [
    'check_symlinks' => true,
],

'logging' => [
    'enabled' => true,
    'detailed' => true,
],
```

### Defense in Depth

1. **Use `safeguard` rule** — All-in-one protection
2. **Enable archive scanning** — Block embedded threats
3. **Block Office macros** — Major malware vector
4. **Enable logging** — Monitor for attacks
5. **Regular updates** — Keep patterns current

---

## Security Logging

All security events are logged with:

```php
[
    'event_type' => 'xxe_detected',
    'threat_level' => 'critical',
    'file' => [
        'name' => 'malicious.svg',
        'size' => '1.2 KB',
        'hash' => 'sha256:abc123...',
    ],
    'user_id' => 42,
    'ip' => '192.168.1.100',
    'threats' => ['XXE attack detected: external entity declaration'],
]
```

### Custom Log Channel

```php
// config/logging.php
'channels' => [
    'security' => [
        'driver' => 'daily',
        'path' => storage_path('logs/security.log'),
        'level' => 'warning',
        'days' => 30,
    ],
],

// config/safeguard.php
'logging' => [
    'channel' => 'security',
],
```

---

## Next Steps

- [Validation Rules](/guide/rules) - All available rules
- [Configuration](/guide/config) - Customize settings
- [API Reference](/api/) - Complete API docs
