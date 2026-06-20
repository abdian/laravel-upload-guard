# API Reference

Complete API reference for Laravel Safeguard.

## String Rules

### safeguard

```php
'file' => 'required|safeguard'
```

All-in-one security validation.

### safeguard_mime

```php
'file' => 'required|safeguard_mime:image/jpeg,image/png'
```

**Parameters:**
- `types` - Comma-separated MIME types

### safeguard_php

```php
'file' => 'required|safeguard_php'
```

Scans for malicious PHP code.

### safeguard_image

```php
'photo' => 'required|safeguard_image'
```

Analyzes image EXIF metadata.

### safeguard_pdf

```php
'document' => 'required|safeguard_pdf'
```

Scans PDF for JavaScript.

### safeguard_dimensions

```php
'image' => 'required|safeguard_dimensions:min_w,min_h,max_w,max_h'
```

**Parameters:**
- `min_width` - Minimum width (pixels)
- `min_height` - Minimum height (pixels)
- `max_width` - Maximum width (pixels)
- `max_height` - Maximum height (pixels)

### safeguard_pages

```php
'pdf' => 'required|safeguard_pages:min,max'
```

**Parameters:**
- `min_pages` - Minimum pages
- `max_pages` - Maximum pages

## Fluent API

### Constructor

```php
use Abdian\UploadGuard\Rules\Safeguard;

$rule = new Safeguard();
```

### File Type Methods

#### imagesOnly()

```php
(new Safeguard())->imagesOnly()
```

Allows: JPEG, PNG, GIF, WebP, BMP, TIFF

#### pdfsOnly()

```php
(new Safeguard())->pdfsOnly()
```

Allows: PDF only

#### documentsOnly()

```php
(new Safeguard())->documentsOnly()
```

Allows: PDF, DOC, DOCX, XLS, XLSX

#### allowedMimes(array $mimes)

```php
(new Safeguard())->allowedMimes(['image/jpeg', 'application/pdf'])
```

**Parameters:**
- `$mimes` - Array of allowed MIME types

### Image Methods

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

Rejects images with GPS data.

#### stripMetadata()

```php
(new Safeguard())->stripMetadata()
```

Removes EXIF/IPTC/XMP metadata.

### PDF Methods

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

Rejects PDFs with JavaScript.

### Security Methods

#### strictMode()

```php
(new Safeguard())->strictMode()
```

Enables strict security validation.

## Method Chaining

All methods return `$this`:

```php
$request->validate([
    'file' => ['required', (new Safeguard())
        ->imagesOnly()
        ->maxDimensions(1920, 1080)
        ->blockGps()
        ->stripMetadata()
    ],
]);
```

## Next Steps

- [Configuration API](/api/config) - Config reference
- [Usage Guide](/guide/usage) - Learn how to use
