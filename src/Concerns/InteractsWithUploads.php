<?php

namespace Abdian\UploadGuard\Concerns;

use Abdian\UploadGuard\Quarantine;
use Abdian\UploadGuard\SecurityLogger;
use Closure;
use Illuminate\Http\UploadedFile;

/**
 * Shared helpers for validation rules: upload-type guards, fail-closed config
 * access, and centralized threat reporting (logging + optional quarantine).
 */
trait InteractsWithUploads
{
    /** @var array<string, bool> */
    private static array $quarantined = [];

    /**
     * Ensure the value is a valid uploaded file, failing otherwise.
     */
    protected function uploadedFileOrFail(string $attribute, mixed $value, Closure $fail): ?UploadedFile
    {
        if (! $value instanceof UploadedFile) {
            $fail("The {$attribute} must be a valid uploaded file.");

            return null;
        }
        if (! $value->isValid()) {
            $fail("The {$attribute} upload failed.");

            return null;
        }

        return $value;
    }

    /**
     * Read config with a fail-closed fallback outside a booted app.
     */
    protected function cfg(string $key, mixed $default = null): mixed
    {
        if (function_exists('config') && function_exists('app')) {
            try {
                $value = config($key, $default);

                return $value ?? $default;
            } catch (\Throwable) {
                return $default;
            }
        }

        return $default;
    }

    /**
     * Report a rejected upload: log the event and (optionally) quarantine it.
     *
     * @param  array<string>  $threats
     */
    protected function report(
        UploadedFile|string $file,
        string $eventType,
        string $level,
        array $threats,
        ?string $detectedType = null
    ): void {
        SecurityLogger::logFileEvent($file, $eventType, $level, 'Safeguard blocked an upload', [
            'threats' => array_slice($threats, 0, 20),
            'detected_type' => $detectedType,
        ]);

        $this->quarantineOnce($file, $threats, $detectedType);
    }

    /**
     * @param  array<string>  $threats
     */
    private function quarantineOnce(UploadedFile|string $file, array $threats, ?string $detectedType): void
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        if ($path === false || $path === '') {
            return;
        }
        if (isset(self::$quarantined[$path])) {
            return;
        }
        self::$quarantined[$path] = true;

        Quarantine::store($file, ['threats' => $threats, 'detected_type' => $detectedType]);
    }

    /**
     * Build a user-facing failure message, optionally including threat detail.
     *
     * @param  array<string>  $threats
     */
    protected function message(string $attribute, string $base, array $threats, bool $showThreats): string
    {
        if ($showThreats && $threats !== []) {
            $list = implode(', ', array_slice($threats, 0, 3));

            return "The {$attribute} {$base}: {$list}";
        }

        return "The {$attribute} {$base}.";
    }
}
