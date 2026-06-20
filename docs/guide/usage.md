# Basic Usage

## The Safeguard Rule

The `safeguard` rule runs all security checks:

```php
$request->validate([
    'file' => 'required|safeguard',
]);
```

## Fluent API

For more control, use the `Safeguard` class:

```php
use Abdian\UploadGuard\Rules\Safeguard;

$request->validate([
    'file' => ['required', (new Safeguard())
        ->imagesOnly()
        ->maxDimensions(1920, 1080)
    ],
]);
```

## File Type Restrictions

### Images Only

```php
'avatar' => ['required', (new Safeguard())->imagesOnly()],
```

Allows: JPEG, PNG, GIF, WebP, BMP, TIFF

### PDFs Only

```php
'document' => ['required', (new Safeguard())->pdfsOnly()],
```

### Documents Only

```php
'file' => ['required', (new Safeguard())->documentsOnly()],
```

Allows: PDF, DOC, DOCX, XLS, XLSX

### Custom MIME Types

```php
'file' => ['required', (new Safeguard())
    ->allowedMimes(['image/jpeg', 'image/png', 'application/pdf'])
],
```

## Image Features

### Dimension Limits

```php
'photo' => ['required', (new Safeguard())
    ->imagesOnly()
    ->maxDimensions(2048, 2048)
    ->minDimensions(100, 100)
],
```

### Block GPS Data

```php
'photo' => ['required', (new Safeguard())
    ->imagesOnly()
    ->blockGps()
],
```

### Strip Metadata

```php
'photo' => ['required', (new Safeguard())
    ->imagesOnly()
    ->stripMetadata()
],
```

## PDF Features

### Page Limits

```php
'contract' => ['required', (new Safeguard())
    ->pdfsOnly()
    ->maxPages(10)
    ->minPages(1)
],
```

### Block JavaScript

```php
'document' => ['required', (new Safeguard())
    ->pdfsOnly()
    ->blockJavaScript()
],
```

## Individual Rules

### MIME Type Validation

```php
'file' => 'required|safeguard_mime:image/jpeg,image/png'
```

### PHP Code Scanning

```php
'file' => 'required|safeguard_php'
```

### Image Security

```php
'photo' => 'required|safeguard_image'
```

### PDF Security

```php
'document' => 'required|safeguard_pdf'
```

## Next Steps

- [Validation Rules](/guide/rules) - Complete rule reference
- [Configuration](/guide/config) - Customize settings
