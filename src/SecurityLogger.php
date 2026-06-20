<?php

namespace Abdian\UploadGuard;

use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;

/**
 * SecurityLogger — centralized, crash-safe logging for threat events.
 *
 * Logging never breaks validation: hashing is guarded, the channel is validated
 * with a fallback, attacker-controlled strings are sanitized against log
 * injection, and the whole log body is wrapped so a logging failure cannot
 * propagate.
 */
class SecurityLogger
{
    public const LEVEL_LOW = 'low';
    public const LEVEL_MEDIUM = 'medium';
    public const LEVEL_HIGH = 'high';
    public const LEVEL_CRITICAL = 'critical';

    public const EVENT_MIME_MISMATCH = 'mime_mismatch';
    public const EVENT_DANGEROUS_FILE = 'dangerous_file';
    public const EVENT_PHP_CODE = 'php_code';
    public const EVENT_SVG_XSS = 'svg_xss';
    public const EVENT_IMAGE_THREAT = 'image_threat';
    public const EVENT_PDF_THREAT = 'pdf_threat';
    public const EVENT_GPS_DETECTED = 'gps_detected';
    public const EVENT_DIMENSION_EXCEEDED = 'dimension_exceeded';
    public const EVENT_PAGE_EXCEEDED = 'page_exceeded';
    public const EVENT_XXE_DETECTED = 'xxe_detected';
    public const EVENT_ARCHIVE_THREAT = 'archive_threat';
    public const EVENT_MACRO_DETECTED = 'macro_detected';
    public const EVENT_SYMLINK_DETECTED = 'symlink_detected';
    public const EVENT_ZIPBOMB_DETECTED = 'zipbomb_detected';
    public const EVENT_RATE_LIMIT = 'rate_limit';

    private const MAX_STRING_LENGTH = 512;

    /**
     * Log a security threat. Never throws.
     *
     * @param  array<string, mixed>  $context
     */
    public static function logThreat(string $eventType, string $level, string $message, array $context = []): void
    {
        try {
            if (! self::config('safeguard.logging.enabled', true)) {
                return;
            }

            $logContext = [
                'event_type' => $eventType,
                'threat_level' => $level,
            ];

            if (self::config('safeguard.logging.detailed', true)) {
                $logContext = array_merge($logContext, self::sanitizeContext($context));
            }

            $logContext['user_id'] = self::currentUserId();
            $ip = self::currentIp();
            if ($ip !== null) {
                $logContext['ip'] = $ip;
            }

            $level = self::mapLevel($level);
            $channel = self::resolveChannel();

            $logger = $channel !== null ? Log::channel($channel) : Log::getFacadeRoot();
            $logger->log($level, self::sanitizeString($message), $logContext);
        } catch (\Throwable) {
            // Logging must never break validation.
        }
    }

    /**
     * Log a threat with file context. Never throws.
     *
     * @param  array<string, mixed>  $additionalContext
     */
    public static function logFileEvent(
        UploadedFile|string $file,
        string $eventType,
        string $level,
        string $message,
        array $additionalContext = []
    ): void {
        try {
            $context = $additionalContext;

            [$name, $path, $size] = self::fileFacts($file);

            $context['file'] = [
                'name' => self::sanitizeString($name),
                'size' => $size !== null ? self::formatBytes($size) : 'unknown',
            ];

            $hash = self::safeHash($path);
            if ($hash !== null) {
                $context['file']['hash'] = $hash;
            }

            self::logThreat($eventType, $level, $message, $context);
        } catch (\Throwable) {
            // never propagate
        }
    }

    /**
     * Strip control characters and cap the length of an attacker-controlled string.
     */
    public static function sanitizeString(string $value): string
    {
        // Remove C0/C1 control characters (incl. CR/LF) and DEL.
        $clean = preg_replace('/[\x00-\x1F\x7F-\x9F]/u', '', $value);
        if ($clean === null) {
            // Invalid UTF-8: fall back to a byte-wise strip.
            $clean = preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '';
        }

        if (mb_strlen($clean) > self::MAX_STRING_LENGTH) {
            $clean = mb_substr($clean, 0, self::MAX_STRING_LENGTH) . '…';
        }

        return $clean;
    }

    /**
     * @param  array<string, mixed>  $context
     * @return array<string, mixed>
     */
    private static function sanitizeContext(array $context): array
    {
        $out = [];
        foreach ($context as $key => $value) {
            $key = self::sanitizeString((string) $key);
            if (is_string($value)) {
                $out[$key] = self::sanitizeString($value);
            } elseif (is_array($value)) {
                $out[$key] = self::sanitizeContext($value);
            } else {
                $out[$key] = $value;
            }
        }

        return $out;
    }

    /**
     * @param  UploadedFile|string  $file
     * @return array{0:string,1:?string,2:?int}
     */
    private static function fileFacts(UploadedFile|string $file): array
    {
        if ($file instanceof UploadedFile) {
            $path = $file->getRealPath();

            return [
                (string) $file->getClientOriginalName(),
                $path === false ? null : $path,
                self::sizeOf($path === false ? null : $path),
            ];
        }

        return [basename($file), $file, self::sizeOf($file)];
    }

    private static function sizeOf(?string $path): ?int
    {
        if ($path === null || ! is_file($path)) {
            return null;
        }
        $size = @filesize($path);

        return $size === false ? null : $size;
    }

    private static function safeHash(?string $path): ?string
    {
        $algorithm = self::config('safeguard.logging.hash_algorithm', 'sha256');
        if (! is_string($algorithm) || ! in_array($algorithm, ['md5', 'sha1', 'sha256'], true)) {
            return null;
        }
        if ($path === null) {
            return null;
        }
        $real = realpath($path);
        if ($real === false || ! is_readable($real)) {
            return null;
        }

        $hash = @hash_file($algorithm, $real);

        return $hash === false ? null : $hash;
    }

    private static function resolveChannel(): ?string
    {
        $channel = self::config('safeguard.logging.channel', null);
        if (! is_string($channel) || $channel === '') {
            return null;
        }
        // Validate that the channel is defined; fall back to the default otherwise.
        $defined = self::config("logging.channels.{$channel}", null);
        if ($defined === null && $channel !== 'stack' && $channel !== 'single' && $channel !== 'daily') {
            return null;
        }

        return $channel;
    }

    private static function mapLevel(string $level): string
    {
        return match ($level) {
            self::LEVEL_CRITICAL => 'critical',
            self::LEVEL_HIGH => 'error',
            self::LEVEL_MEDIUM => 'warning',
            self::LEVEL_LOW => 'info',
            default => 'warning',
        };
    }

    private static function currentUserId(): int|string|null
    {
        try {
            if (function_exists('auth') && auth()->check()) {
                return auth()->id();
            }
        } catch (\Throwable) {
            // no auth context
        }

        return null;
    }

    private static function currentIp(): ?string
    {
        try {
            if (function_exists('request') && request() !== null) {
                $ip = request()->ip();

                return is_string($ip) ? $ip : null;
            }
        } catch (\Throwable) {
            // no request context
        }

        return null;
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

    private static function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $value = (float) $bytes;
        while ($value > 1024 && $i < count($units) - 1) {
            $value /= 1024;
            $i++;
        }

        return round($value, 2) . ' ' . $units[$i];
    }
}
