<?php

namespace Abdian\UploadGuard;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Cache;

/**
 * RateLimiter — DoS guard for upload scanning.
 *
 * Enforces a per-file size ceiling (always) plus per-IP, per-minute caps on the
 * number of files and total bytes (only when an HTTP request context exists).
 * Fails closed on over-limit and degrades safely (skips request-keyed limits)
 * outside an HTTP context.
 */
class RateLimiter
{
    /**
     * Returns null when allowed, or a rejection reason string when over-limit.
     */
    public function check(UploadedFile|string $file): ?string
    {
        if (! $this->enabled()) {
            return null;
        }

        $size = $this->sizeOf($file);

        // Per-file size ceiling — always enforced.
        $maxFile = (int) $this->cfg('max_file_size', 50 * 1024 * 1024);
        if ($maxFile > 0 && $size > $maxFile) {
            return "File exceeds the maximum allowed size ({$size} > {$maxFile} bytes)";
        }

        // Per-minute caps require a request IP + a working cache store.
        $ip = $this->requestIp();
        if ($ip === null) {
            return null; // queue/CLI: skip request-keyed limits, size already enforced
        }

        try {
            $window = $this->minuteWindow();
            $filesKey = "safeguard:rl:files:{$ip}:{$window}";
            $bytesKey = "safeguard:rl:bytes:{$ip}:{$window}";

            $maxFiles = (int) $this->cfg('max_files_per_minute', 60);
            $maxBytes = (int) $this->cfg('max_total_size_per_minute', 200 * 1024 * 1024);

            // Atomic read-modify-write: seed the per-window key (no-op if it
            // already exists) then atomically increment and compare the returned
            // post-increment total against the cap. This prevents concurrent
            // uploads from one IP all reading the same pre-increment value.
            if ($maxFiles > 0) {
                Cache::add($filesKey, 0, 120);
                $files = (int) Cache::increment($filesKey, 1);
                if ($files > $maxFiles) {
                    return 'Upload rate limit exceeded (files per minute)';
                }
            }
            if ($maxBytes > 0) {
                Cache::add($bytesKey, 0, 120);
                $bytes = (int) Cache::increment($bytesKey, $size);
                if ($bytes > $maxBytes) {
                    return 'Upload rate limit exceeded (bytes per minute)';
                }
            }
        } catch (\Throwable) {
            // Cache unavailable: do not block on infrastructure failure; the size
            // ceiling above already provides a bounded guarantee.
            return null;
        }

        return null;
    }

    private function enabled(): bool
    {
        return (bool) $this->cfg('enabled', false);
    }

    private function sizeOf(UploadedFile|string $file): int
    {
        if ($file instanceof UploadedFile) {
            $size = $file->getSize();

            return $size === null || $size === false ? 0 : (int) $size;
        }
        $size = @filesize($file);

        return $size === false ? 0 : $size;
    }

    private function requestIp(): ?string
    {
        try {
            if (function_exists('request') && request() !== null) {
                $ip = request()->ip();

                return is_string($ip) ? $ip : null;
            }
        } catch (\Throwable) {
            // no request bound
        }

        return null;
    }

    private function minuteWindow(): int
    {
        // Deterministic per-minute bucket. time() is acceptable in PHP runtime.
        return intdiv(time(), 60);
    }

    private function cfg(string $key, mixed $default = null): mixed
    {
        if (function_exists('config') && function_exists('app')) {
            try {
                $value = config("safeguard.rate_limiting.{$key}", $default);

                return $value ?? $default;
            } catch (\Throwable) {
                return $default;
            }
        }

        return $default;
    }
}
