# Quick Start

## Basic Usage

The simplest way to use Laravel Safeguard:

```php
use Illuminate\Http\Request;

public function upload(Request $request)
{
    $request->validate([
        'file' => 'required|safeguard',
    ]);

    // File is safe to process
    $file = $request->file('file');
    $path = $file->store('uploads');

    return response()->json(['path' => $path]);
}
```

This single rule performs all security checks:
- Real MIME type detection
- PHP code scanning
- XSS detection
- Image metadata analysis
- PDF security scanning

## Common Examples

### Image Upload

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

### PDF Upload

```php
$request->validate([
    'document' => ['required', (new Safeguard())
        ->pdfsOnly()
        ->maxPages(50)
        ->blockJavaScript()
    ],
]);
```

### Multiple Files

```php
$request->validate([
    'photos' => 'required|array|max:10',
    'photos.*' => ['required', (new Safeguard())
        ->imagesOnly()
        ->maxDimensions(1920, 1080)
    ],
]);
```

## Next Steps

- [Usage Guide](/guide/usage) - Learn all features
- [Validation Rules](/guide/rules) - Complete reference
