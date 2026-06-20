<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\ImageScanner;
use Abdian\UploadGuard\SecurityLogger;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * SafeguardImage — scans raster images for embedded code, metadata threats,
 * decompression bombs, and trailing payloads.
 */
class SafeguardImage implements ValidationRule
{
    use InteractsWithUploads;

    protected bool $blockGps = false;

    protected bool $stripMetadata = false;

    public function __construct(protected bool $showThreats = false)
    {
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $file = $this->uploadedFileOrFail($attribute, $value, $fail);
        if ($file === null) {
            return;
        }
        if (! $this->cfg('safeguard.image_scanning.enabled', true)) {
            return;
        }

        $scanner = new ImageScanner();
        if (! $scanner->isImage($file)) {
            $fail("The {$attribute} is not a valid image file.");

            return;
        }

        $result = $scanner->scan($file);

        if (! $result['safe']) {
            $this->report($file, SecurityLogger::EVENT_IMAGE_THREAT, SecurityLogger::LEVEL_HIGH, $result['threats']);
            $fail($this->message($attribute, 'contains potentially malicious content and cannot be uploaded', $result['threats'], $this->showThreats));

            return;
        }

        if (($this->blockGps || (bool) $this->cfg('safeguard.image_scanning.block_gps', false)) && $result['has_gps']) {
            $this->report($file, SecurityLogger::EVENT_GPS_DETECTED, SecurityLogger::LEVEL_LOW, ['GPS metadata present']);
            $fail("The {$attribute} contains GPS location data. Please remove it before uploading.");

            return;
        }

        if (($this->stripMetadata || (bool) $this->cfg('safeguard.image_scanning.reencode', false))) {
            if (! $scanner->reencode($file)) {
                $fail("The {$attribute} image could not be safely re-encoded.");
            }
        }
    }

    public function blockGps(): self
    {
        $this->blockGps = true;

        return $this;
    }

    public function stripMetadata(): self
    {
        $this->stripMetadata = true;

        return $this;
    }

    public function withThreats(): self
    {
        $this->showThreats = true;

        return $this;
    }
}
