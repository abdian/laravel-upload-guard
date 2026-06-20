<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\ArchiveScanner;
use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\SecurityLogger;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * SafeguardArchive — streams and inspects archive contents (zip bombs, path
 * traversal, dangerous extensions, symlinks, nested archives).
 */
class SafeguardArchive implements ValidationRule
{
    use InteractsWithUploads;

    /** @var array<string> */
    protected array $allowExtensions = [];

    /** @var array<string> */
    protected array $blockExtensions = [];

    /**
     * @param  array<string>  $parameters
     */
    public function __construct(array $parameters = [])
    {
        // String-rule parameters are treated as additional blocked extensions.
        $this->blockExtensions = array_filter(array_map('strval', $parameters));
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $file = $this->uploadedFileOrFail($attribute, $value, $fail);
        if ($file === null) {
            return;
        }

        // Apply per-instance allow/block overrides, then ALWAYS restore the
        // original config — otherwise the merged lists leak to other fields in
        // the same request and accrete across requests in long-running workers
        // (Octane/queue).
        $restore = $this->applyOverrides();

        try {
            $result = (new ArchiveScanner())->scan($file);
        } finally {
            $restore();
        }

        if (! $result['safe']) {
            $this->report($file, SecurityLogger::EVENT_ARCHIVE_THREAT, SecurityLogger::LEVEL_HIGH, $result['threats']);
            $fail($this->message($attribute, 'contains an unsafe archive and cannot be uploaded', $result['threats'], false));
        }
    }

    /**
     * Merge per-instance allow/block lists into config and return a closure that
     * restores the original values (call it in a finally to avoid leakage).
     */
    private function applyOverrides(): callable
    {
        if (! function_exists('config') || ($this->allowExtensions === [] && $this->blockExtensions === [])) {
            return static function (): void {};
        }
        $excludeKey = 'safeguard.archive_scanning.exclude_extensions';
        $blockKey = 'safeguard.archive_scanning.blocked_extensions';
        try {
            $origExclude = config($excludeKey);
            $origBlock = config($blockKey);
            if ($this->allowExtensions !== []) {
                config([$excludeKey => array_values(array_unique(array_merge((array) $origExclude, $this->allowExtensions)))]);
            }
            if ($this->blockExtensions !== []) {
                config([$blockKey => array_values(array_unique(array_merge((array) $origBlock, $this->blockExtensions)))]);
            }

            return static function () use ($excludeKey, $blockKey, $origExclude, $origBlock): void {
                try {
                    config([$excludeKey => $origExclude, $blockKey => $origBlock]);
                } catch (\Throwable) {
                    // ignore in non-Laravel contexts
                }
            };
        } catch (\Throwable) {
            // ignore in non-Laravel contexts
            return static function (): void {};
        }
    }

    /**
     * @param  array<string>  $extensions
     */
    public function allow(array $extensions): self
    {
        $this->allowExtensions = array_map('strtolower', $extensions);

        return $this;
    }

    /**
     * @param  array<string>  $extensions
     */
    public function block(array $extensions): self
    {
        $this->blockExtensions = array_map('strtolower', $extensions);

        return $this;
    }
}
