# Validation Rules

Complete reference for all validation rules.

## String Rules

### safeguard

All-in-one security validation.

```php
'file' => 'required|safeguard'
```

Performs all security checks: MIME detection, PHP scanning, XSS detection, and more.

### safeguard_mime

Validates real MIME type via magic bytes.

```php
'file' => 'required|safeguard_mime:image/jpeg,image/png'
```

### safeguard_php

Scans for malicious PHP code.

```php
'file' => 'required|safeguard_php'
```

### safeguard_svg

Scans SVG for XSS and XXE attacks.

```php
'icon' => 'required|safeguard_svg'
```

Detects:
- Dangerous tags (`<script>`, `<iframe>`, etc.)
- Event handlers (`onload`, `onclick`, etc.)
- XXE attack patterns (entity declarations)
- Obfuscated content

### safeguard_image

Analyzes image EXIF metadata.

```php
'photo' => 'required|safeguard_image'
```

### safeguard_pdf

Scans PDF for JavaScript and threats.

```php
'document' => 'required|safeguard_pdf'
```

### safeguard_archive

Scans archive contents for security threats.

```php
'backup' => 'required|safeguard_archive'
```

Detects:
- Dangerous file extensions (.php, .exe, .bat, etc.)
- Path traversal attacks (`../`)
- Zip bombs (hard cap on actual decompressed bytes; forged sizes can't bypass)
- Excessive file counts

**Parameters:**

```php
// String params are ADDED to the block list (use bare extension names)
'file' => 'safeguard_archive:iso,bin'

// To ALLOW an otherwise-blocked extension, use the fluent rule instead:
'file' => ['required', (new \Abdian\UploadGuard\Rules\SafeguardArchive())->allow(['sh'])]
```

### safeguard_office

Detects macros in Office documents.

```php
'report' => 'required|safeguard_office'
```

Detects:
- VBA macros (vbaProject.bin)
- Macro content types
- ActiveX controls
- Extension spoofing (.docm as .docx)

**Parameters:**

```php
// Allow macros
'file' => 'safeguard_office:allow_macros'

// Allow ActiveX
'file' => 'safeguard_office:allow_activex'
```

### safeguard_dimensions

Validates image dimensions.

```php
'image' => 'required|safeguard_dimensions:100,100,1920,1080'
```

Format: `min_width,min_height,max_width,max_height`

### safeguard_pages

Validates PDF page count.

```php
'pdf' => 'required|safeguard_pages:1,10'
```

Format: `min_pages,max_pages`

---

## Fluent API

### Type Filters

#### imagesOnly()

```php
(new Safeguard())->imagesOnly()
```

#### pdfsOnly()

```php
(new Safeguard())->pdfsOnly()
```

#### documentsOnly()

```php
(new Safeguard())->documentsOnly()
```

#### archivesOnly()

```php
(new Safeguard())->archivesOnly()
```

Allows only archive files and enables archive scanning.

### MIME Control

#### allowedMimes(array $mimes)

```php
(new Safeguard())->allowedMimes(['image/jpeg', 'application/pdf'])
```

#### strictExtensionMatching(bool $enable = true)

```php
(new Safeguard())->strictExtensionMatching()
```

Ensures file extension matches detected MIME type.

### Image Control

#### maxDimensions(int $width, int $height)

```php
(new Safeguard())->maxDimensions(1920, 1080)
```

#### minDimensions(int $width, int $height)

```php
(new Safeguard())->minDimensions(100, 100)
```

#### blockGps()

```php
(new Safeguard())->blockGps()
```

#### stripMetadata()

```php
(new Safeguard())->stripMetadata()
```

### PDF Control

#### maxPages(int $pages)

```php
(new Safeguard())->maxPages(10)
```

#### minPages(int $pages)

```php
(new Safeguard())->minPages(1)
```

#### blockJavaScript()

```php
(new Safeguard())->blockJavaScript()
```

#### blockExternalLinks()

```php
(new Safeguard())->blockExternalLinks()
```

### Archive Control

#### scanArchives()

```php
(new Safeguard())->scanArchives()
```

Enables scanning of archive contents for:
- Dangerous file extensions
- Path traversal attacks
- Zip bombs
- Nested archives

### Office Control

#### blockMacros()

```php
(new Safeguard())->blockMacros()
```

Blocks Office documents containing VBA macros or ActiveX controls.

---

## Usage Examples

### Secure Image Upload

```php
use Abdian\UploadGuard\Rules\Safeguard;

$request->validate([
    'avatar' => ['required', (new Safeguard())
        ->imagesOnly()
        ->maxDimensions(1024, 1024)
        ->blockGps()
        ->stripMetadata()
    ],
]);
```

### Secure Document Upload

```php
$request->validate([
    'document' => ['required', (new Safeguard())
        ->documentsOnly()
        ->blockMacros()
        ->blockJavaScript()
    ],
]);
```

### Secure Archive Upload

```php
$request->validate([
    'backup' => ['required', (new Safeguard())
        ->archivesOnly()
        ->scanArchives()
    ],
]);
```

### Multiple File Types

```php
$request->validate([
    'file' => ['required', (new Safeguard())
        ->allowedMimes([
            'image/jpeg',
            'image/png',
            'application/pdf',
        ])
        ->strictExtensionMatching()
        ->blockMacros()
        ->scanArchives()
    ],
]);
```

---

## Next Steps

- [Configuration](/guide/config) - Customize defaults
- [Security Features](/guide/security) - Detailed security info
- [API Reference](/api/) - Complete API docs
