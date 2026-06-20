<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\ExtensionMimeMap;
use Abdian\UploadGuard\MimeTypeDetector;
use Abdian\UploadGuard\SecurityLogger;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * SafeguardMime — validates a file's real (content-derived) type against an
 * allowlist and blocks dangerous types. Unknown types fail closed.
 */
class SafeguardMime implements ValidationRule
{
    use InteractsWithUploads;

    /** @var array<string> */
    protected array $allowedMimeTypes;

    /**
     * @param  array<string>|string  $allowedMimeTypes
     */
    public function __construct(array|string $allowedMimeTypes = [], protected bool $blockDangerous = true)
    {
        $this->allowedMimeTypes = is_string($allowedMimeTypes)
            ? array_filter(array_map('trim', explode(',', $allowedMimeTypes)))
            : $allowedMimeTypes;
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $file = $this->uploadedFileOrFail($attribute, $value, $fail);
        if ($file === null) {
            return;
        }

        $detector = new MimeTypeDetector();
        $detected = $detector->detect($file);
        $extension = strtolower((string) $file->getClientOriginalExtension());

        // Unknown type fails closed.
        if ($detected === null) {
            $this->report($file, SecurityLogger::EVENT_MIME_MISMATCH, SecurityLogger::LEVEL_MEDIUM, ['Undetermined content type']);
            $fail("The {$attribute} has an undetermined or unsupported content type.");

            return;
        }

        if ($this->blockDangerous && $detector->isDangerous($detected)) {
            $this->report($file, SecurityLogger::EVENT_DANGEROUS_FILE, SecurityLogger::LEVEL_HIGH, ["Dangerous type: {$detected}"], $detected);
            $fail("The {$attribute} file type is not allowed for security reasons.");

            return;
        }

        if ($this->allowedMimeTypes !== [] && ! $this->isAllowed($detected, $extension)) {
            $this->report($file, SecurityLogger::EVENT_MIME_MISMATCH, SecurityLogger::LEVEL_MEDIUM, ["Disallowed type: {$detected}"], $detected);
            $fail("The {$attribute} must be a file of an allowed type. Detected: {$detected}.");
        }
    }

    private function isAllowed(string $detected, string $extension): bool
    {
        foreach ($this->allowedMimeTypes as $allowed) {
            if ($allowed === $detected) {
                return true;
            }
            if (str_ends_with($allowed, '/*') && str_starts_with($detected, rtrim($allowed, '*'))) {
                return true;
            }
        }

        return $extension !== ''
            && ExtensionMimeMap::isValidExtensionForMime($extension, $detected)
            && array_intersect(ExtensionMimeMap::getMimeTypes($extension), $this->allowedMimeTypes) !== [];
    }

    public function allowDangerous(): self
    {
        $this->blockDangerous = false;

        return $this;
    }
}
