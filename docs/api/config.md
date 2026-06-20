# Configuration API

Complete configuration reference.

## General

### default_security_level

**Type:** `string`
**Default:** `'strict'`
**Options:** `'strict'`, `'standard'`

```php
'default_security_level' => 'strict',
```

### max_file_size

**Type:** `int`
**Default:** `10240` (10 MB)

```php
'max_file_size' => 10240,
```

## Images

### images.max_width

**Type:** `int`
**Default:** `4096`

```php
'images' => [
    'max_width' => 4096,
],
```

### images.max_height

**Type:** `int`
**Default:** `4096`

### images.block_gps

**Type:** `boolean`
**Default:** `false`

### images.strip_metadata

**Type:** `boolean`
**Default:** `false`

## PDF

### pdf.max_pages

**Type:** `int`
**Default:** `100`

```php
'pdf' => [
    'max_pages' => 100,
],
```

### pdf.block_javascript

**Type:** `boolean`
**Default:** `true`

## PHP Scanning

### php_scanning.enabled

**Type:** `boolean`
**Default:** `true`

```php
'php_scanning' => [
    'enabled' => true,
],
```

### php_scanning.strict_mode

**Type:** `boolean`
**Default:** `true`

### php_scanning.dangerous_functions

**Type:** `array`
**Default:** `['eval', 'exec', 'system', ...]`

## MIME Types

### allowed_mime_types

**Type:** `array`

```php
'allowed_mime_types' => [
    'image/jpeg',
    'image/png',
    'application/pdf',
],
```

### blocked_extensions

**Type:** `array`

```php
'blocked_extensions' => [
    'exe', 'bat', 'cmd',
],
```

## Logging

### logging.enabled

**Type:** `boolean`
**Default:** `true`

```php
'logging' => [
    'enabled' => true,
    'channel' => 'stack',
],
```

## Environment Variables

```env
SAFEGUARD_ENABLED=true
SAFEGUARD_MAX_FILE_SIZE=10240
SAFEGUARD_BLOCK_GPS=false
SAFEGUARD_PHP_SCANNING=true
```

## Next Steps

- [Rules API](/api/) - Validation rules
- [Configuration Guide](/guide/config) - Usage guide
