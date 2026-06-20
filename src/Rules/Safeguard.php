<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\ArchiveScanner;
use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\ExtensionMimeMap;
use Abdian\UploadGuard\ImageScanner;
use Abdian\UploadGuard\MimeTypeDetector;
use Abdian\UploadGuard\OfficeScanner;
use Abdian\UploadGuard\PdfScanner;
use Abdian\UploadGuard\PhpCodeScanner;
use Abdian\UploadGuard\RateLimiter;
use Abdian\UploadGuard\SecurityLogger;
use Abdian\UploadGuard\SvgScanner;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

/**
 * Safeguard — the fail-closed, single-pass, all-in-one upload validation rule.
 *
 * Pipeline (one detection per file, shared across scanners):
 *   1. rate/size guard (DoS) and max_scan_size policy;
 *   2. content-based type detection (null => untrusted, never "binary safe");
 *   3. MIME/extension policy + dangerous-type blocking;
 *   4. ALWAYS-ON PHP/script code scanning over the raw bytes;
 *   5. type-routed scanning (SVG sanitize, image, PDF, archive, office) using
 *      config-driven defaults (archive + office scanning are ON by default);
 *   6. any scanner exception is treated as a failure (never fail-open).
 */
class Safeguard implements ValidationRule
{
    use InteractsWithUploads;

    protected ?array $allowedMimes = null;

    protected ?int $maxWidth = null;
    protected ?int $maxHeight = null;
    protected ?int $minWidth = null;
    protected ?int $minHeight = null;
    protected ?int $maxPages = null;
    protected ?int $minPages = null;

    protected bool $blockGps = false;
    protected bool $stripMetadata = false;
    protected bool $blockJavaScript = false;
    protected bool $blockExternalLinks = false;
    protected ?bool $strictExtensionMatch = null;

    // null => use config defaults (archive/office scanning are ON by default).
    protected ?bool $scanArchives = null;
    protected ?bool $blockMacros = null;

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $file = $this->uploadedFileOrFail($attribute, $value, $fail);
        if ($file === null) {
            return;
        }

        // 1. DoS guard.
        $rateReason = (new RateLimiter())->check($file);
        if ($rateReason !== null) {
            $this->report($file, SecurityLogger::EVENT_RATE_LIMIT, SecurityLogger::LEVEL_MEDIUM, [$rateReason]);
            $fail("The {$attribute} could not be accepted: {$rateReason}.");

            return;
        }

        // 2. Scan-size policy.
        $size = (int) ($file->getSize() ?: 0);
        $maxScan = (int) $this->cfg('safeguard.max_scan_size', 25 * 1024 * 1024);
        $headerOnly = false;
        if ($maxScan > 0 && $size > $maxScan) {
            $policy = (string) $this->cfg('safeguard.over_cap_policy', 'reject');
            if ($policy !== 'header_only') {
                $this->report($file, SecurityLogger::EVENT_DANGEROUS_FILE, SecurityLogger::LEVEL_MEDIUM, ['Exceeds max scan size']);
                $fail("The {$attribute} is too large to be scanned safely.");

                return;
            }
            $headerOnly = true;
        }

        // 3. Detect once.
        $detector = new MimeTypeDetector();
        $detected = $detector->detect($file);
        $extension = strtolower((string) $file->getClientOriginalExtension());

        // 4. MIME / extension policy.
        if (! $this->enforceMimePolicy($attribute, $file, $detector, $detected, $extension, $fail)) {
            return;
        }

        if ($headerOnly) {
            // Over-cap, header-only mode: type policy enforced, deep scan skipped.
            return;
        }

        // 5. ALWAYS-ON code scanning.
        if (! $this->runScanner($attribute, $file, $fail, 'contains potentially malicious code and cannot be uploaded', SecurityLogger::EVENT_PHP_CODE, $detected, function () use ($file) {
            return app(PhpCodeScanner::class)->scan($file);
        })) {
            return;
        }

        // 6. Type-routed scanning.
        $isSvg = $detected === 'image/svg+xml' || $extension === 'svg' || $extension === 'svgz';
        $isPdf = $detected === 'application/pdf' || $extension === 'pdf';
        $isImage = ! $isSvg && is_string($detected) && str_starts_with($detected, 'image/');

        if ($isSvg) {
            if (! $this->handleSvg($attribute, $file, $fail, $detected)) {
                return;
            }
        }

        if ($isImage) {
            if (! $this->handleImage($attribute, $file, $fail, $detected)) {
                return;
            }
        }

        if ($isPdf) {
            if (! $this->handlePdf($attribute, $file, $fail, $detected)) {
                return;
            }
        }

        // Office vs generic archive (office docs are zip but handled separately).
        $path = $file->getRealPath();
        $office = app(OfficeScanner::class);
        $isOffice = $path !== false && $office->isOfficeDocument($path);

        if ($isOffice && $this->officeEnabled()) {
            if (! $this->handleOffice($attribute, $file, $fail, $detected)) {
                return;
            }
        } elseif (! $isOffice && $this->archiveEnabled() && app(ArchiveScanner::class)->isArchive($file)) {
            if (! $this->runScanner($attribute, $file, $fail, 'contains an unsafe archive and cannot be uploaded', SecurityLogger::EVENT_ARCHIVE_THREAT, $detected, function () use ($file) {
                return app(ArchiveScanner::class)->scan($file);
            })) {
                return;
            }
        }
    }

    private function enforceMimePolicy(string $attribute, UploadedFile $file, MimeTypeDetector $detector, ?string $detected, string $extension, Closure $fail): bool
    {
        // Allowed-types allowlist (e.g. from Laravel's mimes rule).
        if ($this->allowedMimes !== null && $this->allowedMimes !== []) {
            if (! $this->matchesAllowedMimes($detected, $extension)) {
                $this->report($file, SecurityLogger::EVENT_MIME_MISMATCH, SecurityLogger::LEVEL_MEDIUM, ['Disallowed type: ' . ($detected ?? 'unknown')], $detected);
                $fail("The {$attribute} must be a file of an allowed type.");

                return false;
            }
        } elseif ($this->cfg('safeguard.mime_validation.block_dangerous', true) && $detector->isDangerous($detected)) {
            $this->report($file, SecurityLogger::EVENT_DANGEROUS_FILE, SecurityLogger::LEVEL_HIGH, ['Dangerous type: ' . $detected], $detected);
            $fail("The {$attribute} file type is not allowed for security reasons.");

            return false;
        }

        // Block dangerous top-level extensions (active formats that often sniff
        // as plain text, e.g. .hta/.scf/.iqy/.slk) when no allowlist constrains.
        if (($this->allowedMimes === null || $this->allowedMimes === [])
            && $extension !== ''
            && in_array($extension, array_map('strtolower', (array) $this->cfg('safeguard.mime_validation.blocked_extensions', [])), true)) {
            $this->report($file, SecurityLogger::EVENT_DANGEROUS_FILE, SecurityLogger::LEVEL_HIGH, ['Dangerous extension: .' . $extension], $detected);
            $fail("The {$attribute} file type (.{$extension}) is not allowed for security reasons.");

            return false;
        }

        // Fail closed on an undetectable real content type when no allowlist
        // constrains it, if configured. Off by default to avoid rejecting
        // unusual-but-legitimate formats; the always-on code scanner still runs.
        if (($this->allowedMimes === null || $this->allowedMimes === [])
            && $detected === null
            && (bool) $this->cfg('safeguard.mime_validation.block_undetectable', false)) {
            $this->report($file, SecurityLogger::EVENT_MIME_MISMATCH, SecurityLogger::LEVEL_MEDIUM, ['Undetectable content type'], $detected);
            $fail("The {$attribute} file type could not be determined and was rejected.");

            return false;
        }

        // Strict extension/content matching. Tri-state: an explicit
        // strictExtensionMatching(true|false) wins; null falls back to config.
        $strict = $this->strictExtensionMatch ?? (bool) $this->cfg('safeguard.mime_validation.strict_check', true);
        // Generic text/plain content is indistinguishable across text formats
        // (.js/.json/.css/.txt all sniff the same), so it never triggers a
        // mismatch — dangerous text types (text/html, image/svg+xml) are NOT
        // text/plain and are still caught, and the code scanner runs regardless.
        if ($strict && $detected !== null && $detected !== 'text/plain' && $extension !== '') {
            if (! ExtensionMimeMap::isValidExtensionForMime($extension, $detected)) {
                // Only enforce when we actually know the extension family.
                // Unknown extensions (e.g. .md) have no expected MIME set, so we
                // cannot claim a mismatch — content-based dangerous-type and code
                // scanning still apply to them.
                if (ExtensionMimeMap::isKnownExtension($extension)) {
                    $this->report($file, SecurityLogger::EVENT_MIME_MISMATCH, SecurityLogger::LEVEL_MEDIUM, ["Extension .{$extension} != {$detected}"], $detected);
                    $fail("The {$attribute} file extension (.{$extension}) does not match its content type ({$detected}).");

                    return false;
                }
            }
        }

        return true;
    }

    private function matchesAllowedMimes(?string $detected, string $extension): bool
    {
        if ($detected === null) {
            return false; // unknown type is not on any allowlist -> fail closed
        }
        foreach ($this->allowedMimes as $allowed) {
            if ($allowed === $detected) {
                return true;
            }
            if (str_ends_with($allowed, '/*') && str_starts_with($detected, rtrim($allowed, '*'))) {
                return true;
            }
        }

        // Accept when the detected type is a valid content type for the declared extension.
        return $extension !== '' && ExtensionMimeMap::isValidExtensionForMime($extension, $detected)
            && array_intersect(ExtensionMimeMap::getMimeTypes($extension), $this->allowedMimes) !== [];
    }

    private function handleSvg(string $attribute, UploadedFile $file, Closure $fail, ?string $detected): bool
    {
        if (! $this->cfg('safeguard.svg_scanning.enabled', true)) {
            return true;
        }
        try {
            $scanner = app(SvgScanner::class);
            $result = $scanner->scan($file);
            $mode = (string) $this->cfg('safeguard.svg_scanning.mode', 'sanitize');

            if (! $result['safe']) {
                $this->report($file, SecurityLogger::EVENT_SVG_XSS, SecurityLogger::LEVEL_HIGH, $result['threats'], $detected);
                $fail($this->message($attribute, 'contains unsafe SVG content and cannot be uploaded', $result['threats'], false));

                return false;
            }
            // Sanitize-in-place so the stored SVG is the cleaned version.
            if ($mode !== 'reject' && $result['clean'] !== null && $result['modified']) {
                $scanner->sanitizeFile($file);
            }
        } catch (\Throwable $e) {
            $fail("The {$attribute} could not be safely processed as an SVG.");

            return false;
        }

        return true;
    }

    private function handleImage(string $attribute, UploadedFile $file, Closure $fail, ?string $detected): bool
    {
        if (! $this->cfg('safeguard.image_scanning.enabled', true)) {
            return true;
        }
        try {
            $scanner = app(ImageScanner::class);
            $result = $scanner->scan($file);
            if (! $result['safe']) {
                $this->report($file, SecurityLogger::EVENT_IMAGE_THREAT, SecurityLogger::LEVEL_HIGH, $result['threats'], $detected);
                $fail("The {$attribute} image contains potentially malicious content and cannot be uploaded.");

                return false;
            }
            if (($this->blockGps || (bool) $this->cfg('safeguard.image_scanning.block_gps', false)) && $result['has_gps']) {
                $this->report($file, SecurityLogger::EVENT_GPS_DETECTED, SecurityLogger::LEVEL_LOW, ['GPS metadata present'], $detected);
                $fail("The {$attribute} contains GPS location data. Please remove it before uploading.");

                return false;
            }
            // Dimension policy.
            if (! $this->checkDimensions($attribute, $file, $fail)) {
                return false;
            }
            // Optional re-encode (fails loudly if no backend).
            if ((bool) $this->cfg('safeguard.image_scanning.reencode', false)) {
                if (! $scanner->reencode($file)) {
                    $fail("The {$attribute} image could not be safely re-encoded.");

                    return false;
                }
            }
        } catch (\Throwable $e) {
            $fail("The {$attribute} image could not be safely processed.");

            return false;
        }

        return true;
    }

    private function checkDimensions(string $attribute, UploadedFile $file, Closure $fail): bool
    {
        if ($this->maxWidth === null && $this->maxHeight === null && $this->minWidth === null && $this->minHeight === null) {
            return true;
        }
        $rule = new SafeguardDimensions($this->maxWidth, $this->maxHeight, $this->minWidth, $this->minHeight);
        $failed = false;
        $rule->validate($attribute, $file, function ($message) use ($fail, &$failed) {
            $failed = true;
            $fail($message);
        });

        return ! $failed;
    }

    private function handlePdf(string $attribute, UploadedFile $file, Closure $fail, ?string $detected): bool
    {
        if (! $this->cfg('safeguard.pdf_scanning.enabled', true)) {
            return true;
        }
        try {
            $scanner = app(PdfScanner::class);
            $result = $scanner->scan($file);
            if (! $result['safe']) {
                $this->report($file, SecurityLogger::EVENT_PDF_THREAT, SecurityLogger::LEVEL_HIGH, $result['threats'], $detected);
                $fail("The {$attribute} PDF contains potentially malicious content and cannot be uploaded.");

                return false;
            }
            if ($this->blockExternalLinks && $result['has_external_links']) {
                $fail("The {$attribute} PDF contains external links.");

                return false;
            }
            // Page policy.
            if ($this->minPages !== null || $this->maxPages !== null) {
                $rule = new SafeguardPages($this->minPages, $this->maxPages);
                $failed = false;
                $rule->validate($attribute, $file, function ($message) use ($fail, &$failed) {
                    $failed = true;
                    $fail($message);
                });
                if ($failed) {
                    return false;
                }
            }
        } catch (\Throwable $e) {
            $fail("The {$attribute} PDF could not be safely processed.");

            return false;
        }

        return true;
    }

    private function handleOffice(string $attribute, UploadedFile $file, Closure $fail, ?string $detected): bool
    {
        try {
            $scanner = app(OfficeScanner::class);
            if ($this->blockMacros === false) {
                $scanner->allowMacros();
            }
            $result = $scanner->scan($file);
            if (! $result['safe']) {
                $this->report($file, SecurityLogger::EVENT_MACRO_DETECTED, SecurityLogger::LEVEL_HIGH, $result['threats'], $detected);
                $fail("The {$attribute} document contains macros or active content and cannot be uploaded.");

                return false;
            }
        } catch (\Throwable $e) {
            $fail("The {$attribute} document could not be safely processed.");

            return false;
        }

        return true;
    }

    /**
     * Run a scanner returning ['safe'=>bool,'threats'=>[]]; fail-closed on throw.
     */
    private function runScanner(string $attribute, UploadedFile $file, Closure $fail, string $base, string $event, ?string $detected, callable $scan): bool
    {
        try {
            $result = $scan();
        } catch (\Throwable $e) {
            // Scanner exception => block (never fail open).
            $fail("The {$attribute} could not be safely processed.");

            return false;
        }
        if (! ($result['safe'] ?? false)) {
            $threats = $result['threats'] ?? [];
            $this->report($file, $event, SecurityLogger::LEVEL_HIGH, $threats, $detected);
            $fail("The {$attribute} {$base}.");

            return false;
        }

        return true;
    }

    private function archiveEnabled(): bool
    {
        if ($this->scanArchives !== null) {
            return $this->scanArchives;
        }

        return (bool) $this->cfg('safeguard.archive_scanning.enabled', true);
    }

    private function officeEnabled(): bool
    {
        if ($this->blockMacros !== null) {
            return true; // explicit caller intent to engage the office scanner
        }

        return (bool) $this->cfg('safeguard.office_scanning.enabled', true);
    }

    // --- Fluent configuration ------------------------------------------------

    public function allowedMimes(array $mimes): self
    {
        $this->allowedMimes = $mimes;

        return $this;
    }

    public function maxDimensions(int $width, int $height): self
    {
        $this->maxWidth = $width;
        $this->maxHeight = $height;

        return $this;
    }

    public function minDimensions(int $width, int $height): self
    {
        $this->minWidth = $width;
        $this->minHeight = $height;

        return $this;
    }

    public function dimensions(int $minWidth, int $minHeight, int $maxWidth, int $maxHeight): self
    {
        $this->minWidth = $minWidth;
        $this->minHeight = $minHeight;
        $this->maxWidth = $maxWidth;
        $this->maxHeight = $maxHeight;

        return $this;
    }

    public function maxPages(int $pages): self
    {
        $this->maxPages = $pages;

        return $this;
    }

    public function minPages(int $pages): self
    {
        $this->minPages = $pages;

        return $this;
    }

    public function pages(int $min, int $max): self
    {
        $this->minPages = $min;
        $this->maxPages = $max;

        return $this;
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

    public function blockJavaScript(): self
    {
        $this->blockJavaScript = true;

        return $this;
    }

    public function blockExternalLinks(): self
    {
        $this->blockExternalLinks = true;

        return $this;
    }

    public function strictExtensionMatching(bool $enable = true): self
    {
        $this->strictExtensionMatch = $enable;

        return $this;
    }

    public function scanArchives(bool $enable = true): self
    {
        $this->scanArchives = $enable;

        return $this;
    }

    public function blockMacros(bool $enable = true): self
    {
        $this->blockMacros = $enable;

        return $this;
    }

    public function allowMacros(): self
    {
        $this->blockMacros = false;

        return $this;
    }

    public function imagesOnly(): self
    {
        $this->allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp'];

        return $this;
    }

    public function pdfsOnly(): self
    {
        $this->allowedMimes = ['application/pdf'];

        return $this;
    }

    public function documentsOnly(): self
    {
        $this->allowedMimes = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/x-ole-storage',
        ];

        return $this;
    }

    public function archivesOnly(): self
    {
        $this->allowedMimes = [
            'application/zip',
            'application/x-tar',
            'application/gzip',
            'application/x-7z-compressed',
            'application/x-rar-compressed',
            'application/x-bzip2',
        ];
        $this->scanArchives = true;

        return $this;
    }
}
