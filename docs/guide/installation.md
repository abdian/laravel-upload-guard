# Installation

## Requirements

- PHP 8.1 or higher (Laravel 13.x requires PHP 8.3+)
- Laravel 13.x, 12.x, 11.x, or 10.x
- GD or Imagick extension (for image processing)
- Fileinfo extension (for MIME detection)

## Install via Composer

```bash
composer require abdian/laravel-upload-guard
```

The package will automatically register via Laravel's package discovery.

## Publish Configuration (Optional)

```bash
php artisan vendor:publish --tag=safeguard-config
```

This creates `config/safeguard.php` where you can customize security settings.

## Verify Installation

```php
use Illuminate\Http\Request;

Route::post('/upload', function (Request $request) {
    $request->validate([
        'file' => 'required|safeguard',
    ]);

    return 'File is safe!';
});
```

## Next Steps

- [Quick Start](/guide/quick-start) - Start using Safeguard
- [Configuration](/guide/config) - Customize settings
