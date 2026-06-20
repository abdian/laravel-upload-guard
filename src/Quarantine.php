<?php

namespace Abdian\UploadGuard;

use Illuminate\Http\UploadedFile;

/**
 * Quarantine — opt-in preservation of rejected files for forensic analysis.
 *
 * Disabled by default. When enabled, a rejected file is copied to the configured
 * path with a sanitized JSON metadata sidecar. Every operation is wrapped so a
 * quarantine failure NEVER breaks validation and NEVER causes fail-open.
 */
class Quarantine
{
    /**
     * Store a rejected file plus sanitized metadata. Returns true on success.
     *
     * @param  array<string, mixed>  $metadata
     */
    public static function store(UploadedFile|string $file, array $metadata = []): bool
    {
        try {
            if (! self::config('safeguard.quarantine.enabled', false)) {
                return false;
            }

            $dir = self::directory();
            if ($dir === null) {
                return false;
            }
            if (! is_dir($dir) && ! @mkdir($dir, 0700, true) && ! is_dir($dir)) {
                return false;
            }

            $sourcePath = $file instanceof UploadedFile ? $file->getRealPath() : $file;
            if ($sourcePath === false || $sourcePath === '' || ! is_file($sourcePath)) {
                return false;
            }

            $originalName = $file instanceof UploadedFile
                ? (string) $file->getClientOriginalName()
                : basename($file);

            $id = bin2hex(random_bytes(8)) . '-' . time();
            $blobPath = $dir . DIRECTORY_SEPARATOR . $id . '.bin';
            $metaPath = $dir . DIRECTORY_SEPARATOR . $id . '.json';

            // Crash-safe copy: write to a temp file then atomically rename.
            $tmp = $blobPath . '.tmp';
            if (@copy($sourcePath, $tmp) === false) {
                return false;
            }
            if (@rename($tmp, $blobPath) === false) {
                @unlink($tmp);

                return false;
            }
            // Quarantined malware must never inherit a permissive umask (e.g. 0644).
            // Lock the blob to owner-only read/write so it cannot become group/world readable.
            @chmod($blobPath, 0600);

            $record = [
                'id' => $id,
                'original_name' => SecurityLogger::sanitizeString($originalName),
                'detected_type' => isset($metadata['detected_type']) && is_string($metadata['detected_type'])
                    ? SecurityLogger::sanitizeString($metadata['detected_type'])
                    : null,
                'threats' => self::sanitizeThreats($metadata['threats'] ?? []),
                'size' => @filesize($sourcePath) ?: null,
                'quarantined_at' => date('c'),
            ];

            $json = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            if ($json !== false) {
                $tmpMeta = $metaPath . '.tmp';
                if (@file_put_contents($tmpMeta, $json) !== false) {
                    if (@rename($tmpMeta, $metaPath) !== false) {
                        // Metadata may reference threat details; restrict to owner-only as well.
                        @chmod($metaPath, 0600);
                    } else {
                        @unlink($tmpMeta);
                    }
                }
            }

            self::pruneExpired($dir);

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function directory(): ?string
    {
        $configured = self::config('safeguard.quarantine.path', null);
        if (is_string($configured) && $configured !== '') {
            return rtrim($configured, '/\\');
        }

        if (function_exists('storage_path')) {
            try {
                return rtrim(storage_path('app/safeguard-quarantine'), '/\\');
            } catch (\Throwable) {
                return null;
            }
        }

        return null;
    }

    /**
     * @param  mixed  $threats
     * @return array<int, string>
     */
    private static function sanitizeThreats(mixed $threats): array
    {
        if (! is_array($threats)) {
            return [];
        }
        $out = [];
        foreach ($threats as $t) {
            if (is_string($t)) {
                $out[] = SecurityLogger::sanitizeString($t);
            }
        }

        return array_slice($out, 0, 50);
    }

    private static function pruneExpired(string $dir): void
    {
        try {
            $days = (int) self::config('safeguard.quarantine.retention_days', 30);
            if ($days <= 0) {
                return;
            }
            $cutoff = time() - ($days * 86400);
            $entries = @glob($dir . DIRECTORY_SEPARATOR . '*') ?: [];
            foreach ($entries as $entry) {
                if (is_file($entry) && (@filemtime($entry) ?: PHP_INT_MAX) < $cutoff) {
                    @unlink($entry);
                }
            }
        } catch (\Throwable) {
            // best-effort cleanup
        }
    }

    private static function config(string $key, mixed $default = null): mixed
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
}
