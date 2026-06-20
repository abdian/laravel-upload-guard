<?php

namespace Abdian\UploadGuard;

use Abdian\UploadGuard\Support\CompoundFile;
use Illuminate\Http\UploadedFile;

/**
 * MimeTypeDetector — determines a file's real type from its byte structure.
 *
 * Detection is structural and fail-closed:
 *   - a configurable header window (>= 512 bytes) is read and classified by
 *     signature + structure (not by extension or client MIME);
 *   - container families are disambiguated into specific subtypes (OLE, ZIP,
 *     ftyp, RIFF) so legitimate files are not mislabeled;
 *   - an unknown type resolves to null, which callers MUST treat as untrusted
 *     (never as a "safe binary" that bypasses scanning);
 *   - results are memoized per file (path + mtime + size).
 */
class MimeTypeDetector
{
    /** Known BMP DIB header sizes used for structural validation. */
    private const BMP_DIB_SIZES = [12, 40, 52, 56, 64, 108, 124];

    /**
     * Maximum number of memoized detection results retained in the process.
     *
     * Under Octane/queue workers, temp uploads have unique per-request paths,
     * so an unbounded memo would leak memory over the worker's lifetime. The
     * cache is bounded and evicts the oldest entries (FIFO) past this cap.
     */
    private const CACHE_MAX_ENTRIES = 512;

    /** @var array<string, ?string> */
    private static array $cache = [];

    /**
     * Detect the real MIME type, or null when it cannot be determined.
     */
    public function detect(UploadedFile|string $file): ?string
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if ($path === false || $path === '' || ! is_file($path) || ! is_readable($path)) {
            return null;
        }

        $cacheKey = $this->cacheKey($path);
        if ($cacheKey !== null && array_key_exists($cacheKey, self::$cache)) {
            return self::$cache[$cacheKey];
        }

        $result = $this->classify($path);

        if ($cacheKey !== null) {
            self::$cache[$cacheKey] = $result;

            // Bound the memo: evict the oldest entries (FIFO) once over the cap
            // so long-lived workers do not leak memory on unique temp paths.
            while (count(self::$cache) > self::CACHE_MAX_ENTRIES) {
                array_shift(self::$cache);
            }
        }

        return $result;
    }

    /** Clear the detection memo (used in tests). */
    public static function flushCache(): void
    {
        self::$cache = [];
    }

    /** Current number of memoized detection results (used in tests). */
    public static function cacheSize(): int
    {
        return count(self::$cache);
    }

    private function cacheKey(string $path): ?string
    {
        $real = realpath($path);
        if ($real === false) {
            return null;
        }
        $mtime = @filemtime($real);
        $size = @filesize($real);

        return $real . '|' . ($mtime ?: 0) . '|' . ($size ?: 0);
    }

    private function classify(string $path): ?string
    {
        $window = (int) $this->getConfig('safeguard.header_window', 512);
        $window = max(512, $window);

        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }
        $head = fread($handle, $window);
        fclose($handle);
        if ($head === false || $head === '') {
            return null;
        }

        // Custom signatures take precedence (lowercase hex prefixes).
        $custom = $this->getConfig('safeguard.mime_validation.custom_signatures', []);
        if (is_array($custom)) {
            $hex = bin2hex($head);
            foreach ($custom as $sig => $mime) {
                if (is_string($sig) && is_string($mime) && str_starts_with($hex, strtolower($sig))) {
                    return $mime;
                }
            }
        }

        return $this->classifyByStructure($head, $path);
    }

    private function classifyByStructure(string $head, string $path): ?string
    {
        // --- Images -------------------------------------------------------
        if (str_starts_with($head, "\x89PNG\r\n\x1a\n")) {
            return 'image/png';
        }
        if (str_starts_with($head, "\xFF\xD8\xFF")) {
            return 'image/jpeg';
        }
        if (str_starts_with($head, 'GIF87a') || str_starts_with($head, 'GIF89a')) {
            return 'image/gif';
        }
        if (str_starts_with($head, "II\x2A\x00") || str_starts_with($head, "MM\x00\x2A")) {
            return 'image/tiff';
        }
        if (str_starts_with($head, "\x00\x00\x01\x00")) {
            return 'image/x-icon';
        }
        if (str_starts_with($head, 'BM') && $this->looksLikeBmp($head)) {
            return 'image/bmp';
        }

        // --- ftyp / ISO-BMFF ---------------------------------------------
        if (strlen($head) >= 12 && substr($head, 4, 4) === 'ftyp') {
            return $this->detectFtyp($head);
        }

        // --- RIFF ---------------------------------------------------------
        if (str_starts_with($head, 'RIFF') && strlen($head) >= 12) {
            return $this->detectRiff(substr($head, 8, 4));
        }

        // --- PDF ----------------------------------------------------------
        if (str_starts_with($head, '%PDF-')) {
            return 'application/pdf';
        }

        // --- OLE / Compound File -----------------------------------------
        if (str_starts_with($head, CompoundFile::SIGNATURE)) {
            return $this->detectOle($path);
        }

        // --- ZIP family ---------------------------------------------------
        if (str_starts_with($head, "PK\x03\x04") || str_starts_with($head, "PK\x05\x06") || str_starts_with($head, "PK\x07\x08")) {
            return $this->detectZip($path);
        }

        // --- Other archives ----------------------------------------------
        if (str_starts_with($head, "\x1f\x8b")) {
            return 'application/gzip';
        }
        if (str_starts_with($head, 'BZh')) {
            return 'application/x-bzip2';
        }
        if (str_starts_with($head, "\xFD7zXZ\x00")) {
            return 'application/x-xz';
        }
        if (str_starts_with($head, "7z\xBC\xAF\x27\x1C")) {
            return 'application/x-7z-compressed';
        }
        if (str_starts_with($head, "Rar!\x1a\x07")) {
            return 'application/x-rar-compressed';
        }
        if (strlen($head) >= 262 && substr($head, 257, 5) === "ustar") {
            return 'application/x-tar';
        }

        // --- Executables / native binaries -------------------------------
        if (str_starts_with($head, "\x7FELF")) {
            return 'application/x-executable';
        }
        if (str_starts_with($head, 'MZ')) {
            return 'application/x-msdownload';
        }
        if (in_array(substr($head, 0, 4), ["\xFE\xED\xFA\xCE", "\xFE\xED\xFA\xCF", "\xCE\xFA\xED\xFE", "\xCF\xFA\xED\xFE"], true)) {
            return 'application/x-mach-binary';
        }
        if (substr($head, 0, 4) === "\xCA\xFE\xBA\xBE") {
            return 'application/java-vm';
        }

        // --- Text-ish / markup -------------------------------------------
        $textType = $this->detectText($head);
        if ($textType !== null) {
            return $textType;
        }

        // --- Fallback to fileinfo (never trust octet-stream as safe) ------
        return $this->fileinfoFallback($path);
    }

    private function looksLikeBmp(string $head): bool
    {
        if (strlen($head) < 18) {
            return false;
        }
        $fileSize = unpack('V', substr($head, 2, 4))[1];
        $dibSize = unpack('V', substr($head, 14, 4))[1];

        return $fileSize >= 26 && in_array($dibSize, self::BMP_DIB_SIZES, true);
    }

    private function detectFtyp(string $head): string
    {
        $brand = strtolower(trim(substr($head, 8, 4)));

        return match (true) {
            in_array($brand, ['qt'], true) => 'video/quicktime',
            in_array($brand, ['m4a'], true) => 'audio/mp4',
            in_array($brand, ['m4b'], true) => 'audio/mp4',
            in_array($brand, ['m4v'], true) => 'video/x-m4v',
            in_array($brand, ['heic', 'heix', 'mif1', 'msf1', 'heim', 'heis'], true) => 'image/heic',
            in_array($brand, ['heif'], true) => 'image/heif',
            in_array($brand, ['avif', 'avis'], true) => 'image/avif',
            default => 'video/mp4',
        };
    }

    private function detectRiff(string $format): string
    {
        return match ($format) {
            'WEBP' => 'image/webp',
            'AVI ' => 'video/x-msvideo',
            'WAVE' => 'audio/wav',
            default => 'application/octet-stream',
        };
    }

    private function detectOle(string $path): string
    {
        $cf = CompoundFile::open($path);
        if ($cf === null) {
            return 'application/x-ole-storage';
        }
        $subtype = $cf->detectOleSubtype();

        return $subtype ?? 'application/x-ole-storage';
    }

    private function detectZip(string $path): string
    {
        if (! class_exists(\ZipArchive::class)) {
            return 'application/zip';
        }

        $zip = new \ZipArchive();
        if ($zip->open($path) !== true) {
            return 'application/zip';
        }

        try {
            // EPUB / ODF declare their type in a "mimetype" entry.
            $mimeEntry = $zip->getFromName('mimetype');
            if ($mimeEntry !== false) {
                $mimeEntry = trim($mimeEntry);
                if ($mimeEntry === 'application/epub+zip' || str_starts_with($mimeEntry, 'application/vnd.oasis.opendocument')) {
                    return $mimeEntry;
                }
            }

            // Java / Android archives.
            if ($zip->locateName('AndroidManifest.xml', \ZipArchive::FL_NOCASE) !== false
                || $zip->locateName('classes.dex', \ZipArchive::FL_NOCASE) !== false) {
                return 'application/vnd.android.package-archive';
            }
            if ($zip->locateName('META-INF/MANIFEST.MF', \ZipArchive::FL_NOCASE) !== false) {
                return 'application/java-archive';
            }

            // Office Open XML.
            $ctIndex = $zip->locateName('[Content_Types].xml', \ZipArchive::FL_NOCASE);
            if ($ctIndex !== false) {
                $ct = $zip->getFromIndex($ctIndex);

                return $this->officeTypeFromContentTypes(is_string($ct) ? $ct : '', $zip);
            }
        } finally {
            $zip->close();
        }

        return 'application/zip';
    }

    private function officeTypeFromContentTypes(string $contentTypes, \ZipArchive $zip): string
    {
        $ct = strtolower($contentTypes);
        if (str_contains($ct, 'wordprocessingml') || $zip->locateName('word/document.xml', \ZipArchive::FL_NOCASE) !== false) {
            return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        }
        if (str_contains($ct, 'spreadsheetml') || $zip->locateName('xl/workbook.xml', \ZipArchive::FL_NOCASE) !== false) {
            return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        }
        if (str_contains($ct, 'presentationml') || $zip->locateName('ppt/presentation.xml', \ZipArchive::FL_NOCASE) !== false) {
            return 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        }

        // Has an OPC content-types part but unknown subtype: still an Office package.
        return 'application/vnd.openxmlformats-officedocument';
    }

    private function detectText(string $head): ?string
    {
        // Strip a leading BOM.
        $trimmed = preg_replace('/^(\xEF\xBB\xBF|\xFF\xFE|\xFE\xFF)/', '', $head) ?? $head;
        $lead = ltrim($trimmed);

        if ($lead === '') {
            return 'text/plain';
        }

        // Markup detection.
        if (preg_match('/^<\?xml\b/i', $lead) || preg_match('/^<svg\b/i', $lead) || preg_match('/^<!DOCTYPE\s+svg/i', $lead)) {
            if (preg_match('/<svg\b/i', $head)) {
                return 'image/svg+xml';
            }

            return 'text/xml';
        }
        if (preg_match('/^<(!DOCTYPE\s+html|html|head|body)\b/i', $lead)) {
            return 'text/html';
        }
        if (str_starts_with($lead, '#!')) {
            return 'text/x-shellscript';
        }

        // Markup that does not start at byte 0 — e.g. a leading comment, BOM, or
        // whitespace before <html>/<svg>. A security validator must classify these
        // by their active type, not as inert text (comment-prefixed HTML/SVG is a
        // classic content-sniffing XSS smuggling trick).
        if (preg_match('/<svg\b/i', $head)) {
            return 'image/svg+xml';
        }
        if (preg_match('/<(?:!DOCTYPE\s+html|html|head|body|iframe|script)\b/i', $head)) {
            return 'text/html';
        }

        // Printable-content heuristic → treat as plain text.
        if ($this->isProbablyText($head)) {
            return 'text/plain';
        }

        return null;
    }

    private function isProbablyText(string $bytes): bool
    {
        if ($bytes === '') {
            return false;
        }
        // Reject if it contains NUL bytes (typical of binary formats).
        if (str_contains($bytes, "\x00")) {
            return false;
        }
        $sample = substr($bytes, 0, 512);
        $control = 0;
        $len = strlen($sample);
        for ($i = 0; $i < $len; $i++) {
            $c = ord($sample[$i]);
            if ($c < 9 || ($c > 13 && $c < 32)) {
                $control++;
            }
        }

        return $len > 0 && ($control / $len) < 0.05;
    }

    private function fileinfoFallback(string $path): ?string
    {
        if (! function_exists('finfo_open')) {
            if (function_exists('mime_content_type')) {
                $type = @mime_content_type($path);

                return $this->normalizeFallback($type === false ? null : $type);
            }

            return null;
        }

        $finfo = @finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo === false) {
            return null;
        }
        $type = @finfo_file($finfo, $path);
        finfo_close($finfo);

        return $this->normalizeFallback($type === false ? null : $type);
    }

    private function normalizeFallback(?string $type): ?string
    {
        if ($type === null || $type === '') {
            return null;
        }
        // octet-stream means "unknown" — fail closed (do not treat as safe).
        if ($type === 'application/octet-stream') {
            return null;
        }

        return $type;
    }

    /**
     * Whether a MIME type is configured as dangerous and should be blocked.
     */
    public function isDangerous(?string $mimeType): bool
    {
        if ($mimeType === null) {
            return false; // unknown is handled by the orchestrator's fail-closed path
        }

        $defaults = [
            'application/x-msdownload', 'application/x-msdos-program', 'application/x-executable',
            'application/x-elf', 'application/x-sharedlib', 'application/x-mach-binary',
            'application/x-dosexec', 'application/vnd.microsoft.portable-executable',
            'application/x-php', 'text/x-php', 'application/x-httpd-php', 'application/x-httpd-php-source',
            'text/x-shellscript', 'application/x-sh', 'application/x-csh',
            'application/x-perl', 'text/x-perl', 'application/x-python', 'text/x-python',
            'application/x-ruby', 'text/x-ruby', 'text/x-jsp',
            'application/java-archive', 'application/java-vm', 'application/vnd.android.package-archive',
            'application/x-bat', 'application/x-msi',
        ];

        $dangerous = $this->getConfig('safeguard.mime_validation.dangerous_types', $defaults);
        if (! is_array($dangerous) || $dangerous === []) {
            $dangerous = $defaults;
        }

        return in_array($mimeType, $dangerous, true);
    }

    /**
     * Informational: whether a detected type is a binary media container.
     *
     * NOTE: this is NOT a security gate. Code scanning runs on every upload
     * regardless of this method's result.
     */
    public function isBinaryFile(UploadedFile|string $file): bool
    {
        $mime = $this->detect($file);
        if ($mime === null) {
            return false;
        }

        return (bool) preg_match('#^(image|video|audio)/#', $mime)
            || in_array($mime, [
                'application/pdf', 'application/zip', 'application/gzip', 'application/x-bzip2',
                'application/x-7z-compressed', 'application/x-rar-compressed', 'application/x-xz',
                'application/x-tar',
            ], true);
    }

    /**
     * Config accessor that degrades safely outside a booted Laravel app.
     */
    protected function getConfig(string $key, mixed $default = null): mixed
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
