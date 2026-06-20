<?php

namespace Abdian\UploadGuard;

use Abdian\UploadGuard\Concerns\ValidatesFileAccess;
use Illuminate\Http\UploadedFile;

/**
 * ArchiveScanner — fail-closed inspection of uploaded archives.
 *
 * Key properties:
 *   - Zip-bomb / size limits are enforced by STREAMING each entry through a
 *     bounded reader and counting ACTUAL decompressed bytes against a hard cap.
 *     Central-directory sizes are never trusted (only used to flag mismatches).
 *   - Every dotted segment of each (normalized) entry name is checked against
 *     the dangerous-extension blocklist; traversal (both separators), absolute
 *     paths, NTFS ADS, and symlink/hardlink entries are rejected.
 *   - Nested archives are actually recursed within the depth cap.
 *   - Detected-but-unsupported or encrypted archives are rejected, not passed.
 */
class ArchiveScanner
{
    use ValidatesFileAccess;

    private const CHUNK = 8192;

    /**
     * @return array{safe: bool, threats: array<string>}
     */
    public function scan(UploadedFile|string $file, int $depth = 0): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        // The decompression budget is GLOBAL across the entire nesting tree:
        // a single cap is established at the top-level call and drawn down by
        // every nested archive, so total decompressed work can never exceed it.
        $remaining = $this->byteCap();

        return $this->scanInternal($path, $depth, $remaining);
    }

    /**
     * Internal entry point that threads the SHARED remaining-byte budget by
     * reference through every (recursive) scan so all decompressed bytes draw
     * down one global cap.
     *
     * @return array{safe: bool, threats: array<string>}
     */
    private function scanInternal(string|false $path, int $depth, int &$remaining): array
    {
        if ($path === false || $path === '' || ! is_file($path) || ! is_readable($path)) {
            return $this->result(false, ['File cannot be read']);
        }
        if ($depth === 0 && ! $this->validateFileAccess($path)) {
            return $this->result(false, [$this->getFileAccessFailureReason($path)]);
        }

        $type = $this->archiveType($path);
        if ($type === null) {
            return $this->result(false, ['Not a recognized archive or unable to inspect']);
        }

        return match ($type) {
            'zip' => $this->scanZip($path, $depth, $remaining),
            'tar' => $this->scanTar($path, $depth, $remaining),
            'gzip' => $this->scanGzip($path, $depth, $remaining),
            // Formats we cannot stream-inspect safely are rejected, not passed.
            default => $this->result(false, ["Unsupported or uninspectable archive format: {$type}"]),
        };
    }

    public function isArchive(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        if ($path === false || ! is_file($path)) {
            return false;
        }

        return $this->archiveType($path) !== null;
    }

    private function archiveType(string $path): ?string
    {
        $head = @file_get_contents($path, false, null, 0, 512);
        if ($head === false) {
            return null;
        }

        if (str_starts_with($head, "PK\x03\x04") || str_starts_with($head, "PK\x05\x06") || str_starts_with($head, "PK\x07\x08")) {
            return 'zip';
        }
        if (str_starts_with($head, "\x1f\x8b")) {
            return 'gzip';
        }
        if (strlen($head) >= 262 && substr($head, 257, 5) === 'ustar') {
            return 'tar';
        }
        if (str_starts_with($head, "7z\xBC\xAF\x27\x1C")) {
            return '7z';
        }
        if (str_starts_with($head, "Rar!\x1a\x07")) {
            return 'rar';
        }
        if (str_starts_with($head, 'BZh')) {
            return 'bzip2';
        }
        if (str_starts_with($head, 'MSCF')) {
            return 'cab';
        }

        return null;
    }

    /**
     * @return array{safe: bool, threats: array<string>}
     */
    private function scanZip(string $path, int $depth, int &$remaining): array
    {
        if (! class_exists(\ZipArchive::class)) {
            return $this->result(false, ['ext-zip is required to inspect ZIP archives']);
        }

        $zip = new \ZipArchive();
        if ($zip->open($path) !== true) {
            return $this->result(false, ['ZIP archive could not be opened (corrupt or encrypted)']);
        }

        $threats = [];
        $cap = $this->byteCap();
        $maxFiles = (int) $this->getConfig('safeguard.archive_scanning.max_files_count', 10000);
        $count = $zip->numFiles;

        if ($maxFiles > 0 && $count > $maxFiles) {
            $zip->close();

            return $this->result(false, ["Archive contains too many entries ({$count})"]);
        }

        for ($i = 0; $i < $count; $i++) {
            $name = $zip->getNameIndex($i);
            if ($name === false) {
                $threats[] = 'Unreadable archive entry';
                continue;
            }

            // Symlink / hardlink entries (unix mode S_IFLNK in external attrs).
            if ($this->isZipSymlink($zip, $i)) {
                $threats[] = "Symlink entry rejected: {$this->display($name)}";
                continue;
            }

            // Encrypted entries cannot be inspected -> fail closed.
            $stat = $zip->statIndex($i);
            if (is_array($stat) && isset($stat['encryption_method']) && $stat['encryption_method'] !== \ZipArchive::EM_NONE) {
                $threats[] = "Encrypted archive entry cannot be inspected: {$this->display($name)}";
                continue;
            }

            // Path / extension checks on the normalized name.
            $nameThreat = $this->checkEntryName($name);
            if ($nameThreat !== null) {
                $threats[] = $nameThreat;
                continue;
            }

            // Directory entries have no content.
            if (str_ends_with($name, '/')) {
                continue;
            }

            // Stream the entry, counting ACTUAL decompressed bytes against the
            // SHARED global budget so nested archives cannot each get a fresh cap.
            [$actual, $bytes, $bombed, $streamFailed] = $this->streamZipEntry($zip, $name, $remaining, $depth);
            $remaining -= $actual;

            // A present entry whose stream cannot be opened cannot be inspected
            // -> fail closed rather than silently treating it as safe.
            if ($streamFailed) {
                $threats[] = "Archive entry could not be read for inspection: {$this->display($name)}";
                continue;
            }

            if ($bombed || $remaining < 0) {
                $threats[] = "Decompression bomb detected (exceeded {$cap} bytes): {$this->display($name)}";
                break;
            }

            // Declared-vs-actual mismatch (forged central-directory size).
            $declared = is_array($stat) ? (int) ($stat['size'] ?? 0) : 0;
            if ($declared > 0 && $actual > 0 && ($actual > $declared * 4 || $declared > $actual * 4)) {
                $threats[] = "Declared/actual size mismatch: {$this->display($name)} (declared {$declared}, actual {$actual})";
            }

            // Scan the DECOMPRESSED bytes for PHP/script code openers: a webshell
            // compressed inside the archive must not pass just because its entry
            // name and size look benign.
            if ($bytes !== null) {
                $codeThreat = $this->scanDecompressedForCode($bytes);
                if ($codeThreat !== null) {
                    $threats[] = "Embedded code in archive entry: {$this->display($name)} ({$codeThreat})";
                }
            }

            // Recurse nested archives within the depth cap.
            if ($bytes !== null) {
                $nested = $this->maybeRecurse($name, $bytes, $depth, $remaining);
                if ($nested !== null) {
                    $threats = array_merge($threats, $nested);
                }
            }
        }

        $zip->close();

        return $this->result($threats === [], $threats);
    }

    private function isZipSymlink(\ZipArchive $zip, int $index): bool
    {
        $opsys = 0;
        $attr = 0;
        if (! @$zip->getExternalAttributesIndex($index, $opsys, $attr)) {
            return false;
        }
        // Unix permissions live in the high 16 bits; S_IFLNK = 0xA000.
        $unixMode = ($attr >> 16) & 0xF000;

        return $unixMode === 0xA000;
    }

    /**
     * @return array{0:int,1:?string,2:bool,3:bool} [actualBytes, capturedBytesOrNull, bombed, streamFailed]
     */
    private function streamZipEntry(\ZipArchive $zip, string $name, int $remaining, int $depth): array
    {
        if ($remaining <= 0) {
            return [0, null, true, false];
        }

        // A present, non-encrypted, non-directory entry whose stream cannot be
        // opened cannot be inspected: signal failure so the caller fails closed.
        $stream = @$zip->getStream($name);
        if ($stream === false) {
            return [0, null, false, true];
        }

        $actual = 0;
        // At/over the depth cap we only need enough bytes to SNIFF a nested
        // archive header (so it can be fail-closed rejected) and to code-scan
        // the decompressed content; we do not need the full nested capture.
        $captureLimit = $depth < $this->maxDepth()
            ? $this->nestedCaptureLimit()
            : $this->codeScanCaptureLimit();
        $capture = '';
        $bombed = false;

        while (! feof($stream)) {
            $chunk = fread($stream, self::CHUNK);
            if ($chunk === false) {
                break;
            }
            $actual += strlen($chunk);
            if (strlen($capture) < $captureLimit) {
                $capture .= substr($chunk, 0, $captureLimit - strlen($capture));
            }
            if ($actual > $remaining) {
                $bombed = true;
                break;
            }
        }
        fclose($stream);

        return [$actual, $capture === '' ? null : $capture, $bombed, false];
    }

    /**
     * Recurse into a nested archive if the captured bytes look like one.
     *
     * @return array<string>|null
     */
    private function maybeRecurse(string $name, string $bytes, int $depth, int &$remaining): ?array
    {
        $looksArchive = str_starts_with($bytes, "PK\x03\x04")
            || str_starts_with($bytes, "\x1f\x8b")
            || (strlen($bytes) >= 262 && substr($bytes, 257, 5) === 'ustar');

        if (! $looksArchive) {
            return null;
        }

        // FAIL-CLOSED: a nested archive deeper than the cap cannot be inspected,
        // so any threat wrapped in N+1 layers would otherwise pass. Reject it.
        if ($depth >= $this->maxDepth()) {
            return ['Archive nesting exceeds maximum depth'];
        }

        $tmp = tempnam(sys_get_temp_dir(), 'sgnest');
        if ($tmp === false) {
            return ['Nested archive could not be inspected'];
        }

        // A short/failed write would leave a truncated copy: fail closed rather
        // than scan a partial archive.
        $written = file_put_contents($tmp, $bytes);
        if ($written === false || $written !== strlen($bytes)) {
            @unlink($tmp);

            return ['Nested archive could not be written for inspection'];
        }

        try {
            $nested = $this->scanInternal($tmp, $depth + 1, $remaining);
        } finally {
            @unlink($tmp);
        }

        if ($nested['safe']) {
            return null;
        }

        return array_map(static fn ($t) => "Nested archive ({$name}): {$t}", $nested['threats']);
    }

    /**
     * @return array{safe: bool, threats: array<string>}
     */
    private function scanTar(string $path, int $depth, int &$remaining): array
    {
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return $this->result(false, ['TAR could not be opened']);
        }

        $threats = [];
        $cap = $this->byteCap();
        $fileSize = filesize($path);
        if ($fileSize === false) {
            fclose($handle);

            return $this->result(false, ['TAR size could not be determined']);
        }

        // Pending long pathname / linkname carried over from a GNU 'L'/'K'
        // extended header that applies to the NEXT regular entry.
        $pendingLongName = null;
        $pendingLongLink = null;

        while (! feof($handle)) {
            $header = fread($handle, 512);
            if ($header === false || strlen($header) < 512 || trim($header) === '') {
                break;
            }
            $name = trim(substr($header, 0, 100), "\0");
            if ($name === '') {
                break;
            }
            $sizeOctal = trim(substr($header, 124, 12), "\0 ");
            // Reject non-octal / unparseable declared sizes outright.
            if ($sizeOctal !== '' && ! preg_match('/^[0-7]+$/', $sizeOctal)) {
                $threats[] = "Malformed TAR entry size: {$this->display($name)}";
                break;
            }
            $size = $sizeOctal === '' ? 0 : (int) octdec($sizeOctal);
            $typeflag = substr($header, 156, 1);

            $blocks = (int) ceil($size / 512);
            $bodyBytes = $blocks * 512;

            // Validate the declared body does not run past EOF before reading:
            // an impossible/oversized declared size is a desync/forgery -> threat.
            if ($bodyBytes > 0) {
                $pos = ftell($handle);
                if ($pos === false || $pos + $bodyBytes > $fileSize) {
                    $threats[] = "TAR entry size runs past end of archive: {$this->display($name)}";
                    break;
                }
            }

            // GNU extended headers: typeflag 'L' = long name, 'K' = long linkname.
            // The entry's DATA block holds the real (possibly very long) pathname
            // that applies to the NEXT entry. Capture it and skip to that entry.
            if ($typeflag === 'L' || $typeflag === 'K') {
                $long = $bodyBytes > 0 ? (string) fread($handle, $bodyBytes) : '';
                $long = trim(substr($long, 0, $size), "\0");
                if ($typeflag === 'L') {
                    $pendingLongName = $long;
                } else {
                    $pendingLongLink = $long;
                }
                // Draw the extended-header body down the SHARED global budget too.
                $remaining -= $size;
                if ($remaining < 0) {
                    $threats[] = "Decompression bomb detected (exceeded {$cap} bytes)";
                    break;
                }
                continue;
            }

            // Resolve the FULL entry name BEFORE any name check:
            //   1. a pending GNU LongName overrides the truncated 100-byte name;
            //   2. otherwise the 155-byte ustar PREFIX (offset 345) is prepended.
            if ($pendingLongName !== null) {
                $name = $pendingLongName;
            } else {
                $prefix = trim(substr($header, 345, 155), "\0");
                if ($prefix !== '') {
                    $name = $prefix . '/' . $name;
                }
            }
            $linkname = $pendingLongLink ?? trim(substr($header, 157, 100), "\0");
            $pendingLongName = null;
            $pendingLongLink = null;

            if ($typeflag === '2' || $typeflag === '1') {
                $threats[] = "Symlink/hardlink entry rejected: {$this->display($name)}";
                // Also vet the (possibly long) link TARGET for traversal.
                if ($linkname !== '') {
                    $linkThreat = $this->checkEntryName($linkname);
                    if ($linkThreat !== null) {
                        $threats[] = $linkThreat;
                    }
                }
            } else {
                $nameThreat = $this->checkEntryName($name);
                if ($nameThreat !== null) {
                    $threats[] = $nameThreat;
                }
            }

            // Draw the declared body size down the SHARED global budget.
            $remaining -= $size;
            if ($remaining < 0) {
                $threats[] = "Decompression bomb detected (exceeded {$cap} bytes)";
                break;
            }

            // Read the body (bounded) to code-scan it, then skip any remainder.
            if ($bodyBytes > 0) {
                $scanLimit = min($size, $this->codeScanCaptureLimit());
                $body = $scanLimit > 0 ? (string) fread($handle, (int) $scanLimit) : '';
                $codeThreat = $this->scanDecompressedForCode($body);
                if ($codeThreat !== null) {
                    $threats[] = "Embedded code in archive entry: {$this->display($name)} ({$codeThreat})";
                }
                $consumed = strlen($body);
                if ($bodyBytes - $consumed > 0) {
                    fseek($handle, $bodyBytes - $consumed, SEEK_CUR);
                }
            }
        }
        fclose($handle);

        return $this->result($threats === [], $threats);
    }

    /**
     * @return array{safe: bool, threats: array<string>}
     */
    private function scanGzip(string $path, int $depth, int &$remaining): array
    {
        $threats = [];

        // Check the embedded original filename (FNAME flag) extension.
        $head = @file_get_contents($path, false, null, 0, 512);
        if ($head !== false && strlen($head) > 10 && (ord($head[3]) & 0x08)) {
            $end = strpos($head, "\0", 10);
            if ($end !== false) {
                $inner = substr($head, 10, $end - 10);
                $nameThreat = $this->checkEntryName($inner);
                if ($nameThreat !== null) {
                    $threats[] = $nameThreat;
                }
            }
        }

        // Bounded decompression to detect bombs and recurse tar.gz.
        $cap = $this->byteCap();
        $gz = @gzopen($path, 'rb');
        if ($gz === false) {
            return $this->result(false, ['GZIP could not be opened']);
        }
        $capture = '';
        $captureLimit = $this->nestedCaptureLimit();
        while (! gzeof($gz)) {
            $chunk = gzread($gz, self::CHUNK);
            if ($chunk === false || $chunk === '') {
                break;
            }
            // Draw decompressed bytes down the SHARED global budget.
            $remaining -= strlen($chunk);
            if (strlen($capture) < $captureLimit) {
                $capture .= substr($chunk, 0, $captureLimit - strlen($capture));
            }
            if ($remaining < 0) {
                $threats[] = "Decompression bomb detected (exceeded {$cap} bytes)";
                break;
            }
        }
        gzclose($gz);

        // Scan the INFLATED bytes for PHP/script code openers: a webshell hidden
        // inside a .gz must not pass just because the gzip wrapper looks benign.
        $codeThreat = $this->scanDecompressedForCode($capture);
        if ($codeThreat !== null) {
            $threats[] = "Embedded code in gzip content ({$codeThreat})";
        }

        if ($threats === [] && $depth < $this->maxDepth() && strlen($capture) >= 262 && substr($capture, 257, 5) === 'ustar') {
            $nested = $this->maybeRecurse('gzip-content.tar', $capture, $depth, $remaining);
            if ($nested !== null) {
                $threats = array_merge($threats, $nested);
            }
        }

        return $this->result($threats === [], $threats);
    }

    /**
     * Validate a single entry name. Returns a threat message or null if clean.
     */
    private function checkEntryName(string $name): ?string
    {
        // Normalize separators and detect traversal / absolute paths.
        $unified = str_replace('\\', '/', $name);

        if (str_contains($name, "\0")) {
            return "Null byte in entry name: {$this->display($name)}";
        }
        if (preg_match('#(^|/)\.\.(/|$)#', $unified)) {
            return "Path traversal entry rejected: {$this->display($name)}";
        }
        if (str_starts_with($unified, '/') || preg_match('#^[A-Za-z]:/#', $unified) || str_starts_with($name, '\\\\')) {
            return "Absolute path entry rejected: {$this->display($name)}";
        }

        $blocked = array_map('strtolower', (array) $this->getConfig('safeguard.archive_scanning.blocked_extensions', []));
        $exclude = array_map('strtolower', (array) $this->getConfig('safeguard.archive_scanning.exclude_extensions', []));
        $blocked = array_diff($blocked, $exclude);
        $blockedNames = array_map('strtolower', (array) $this->getConfig('safeguard.archive_scanning.blocked_filenames', []));

        foreach (explode('/', $unified) as $segment) {
            if ($segment === '') {
                continue;
            }

            // Strip NTFS ADS (everything after a colon) and trailing junk.
            $primary = $segment;
            $colon = strpos($primary, ':');
            if ($colon !== false) {
                $primary = substr($primary, 0, $colon);
            }
            $primary = rtrim($primary, " \t.\r\n");
            $lowerSegment = strtolower($primary);

            if (in_array($lowerSegment, $blockedNames, true) || in_array(strtolower($segment), $blockedNames, true)) {
                return "Blocked filename in archive: {$this->display($segment)}";
            }

            // Check EVERY dotted sub-segment against the blocklist. Strip trailing
            // non-alphanumeric bytes (NUL, control chars, unicode, spaces) so a
            // name like "a.php\xc2\xa0" or "shell.php\x00" cannot smuggle a
            // dangerous extension past an exact-match blocklist.
            foreach (explode('.', $lowerSegment) as $part) {
                $part = preg_replace('/[^a-z0-9]+$/', '', $part) ?? $part;
                if ($part !== '' && in_array($part, $blocked, true)) {
                    return "Dangerous file extension in archive: .{$part} ({$this->display($segment)})";
                }
            }
        }

        return null;
    }

    private function byteCap(): int
    {
        $cap = (int) $this->getConfig('safeguard.archive_scanning.max_decompressed_size', 500 * 1024 * 1024);

        return $cap > 0 ? $cap : PHP_INT_MAX;
    }

    private function maxDepth(): int
    {
        return (int) $this->getConfig('safeguard.archive_scanning.max_nesting_depth', 3);
    }

    private function nestedCaptureLimit(): int
    {
        // Cap on bytes captured for nested-archive recursion.
        return min($this->byteCap(), 64 * 1024 * 1024);
    }

    private function codeScanCaptureLimit(): int
    {
        // Bytes captured/inspected for embedded-code detection per entry. A code
        // opener appears early; cap the work but stay above any archive magic so
        // nested-archive sniffing still functions at the depth boundary.
        return min($this->byteCap(), 1024 * 1024);
    }

    /**
     * Scan already-decompressed bytes for PHP/script code openers. Returns a
     * short threat label or null when clean. Delegates to PhpCodeScanner so the
     * opener set (and any config) stays in one place; falls back to inline
     * opener regexes if a temp file cannot be written.
     */
    private function scanDecompressedForCode(string $bytes): ?string
    {
        if ($bytes === '') {
            return null;
        }

        $tmp = tempnam(sys_get_temp_dir(), 'sgcode');
        if ($tmp !== false) {
            $written = @file_put_contents($tmp, $bytes);
            if ($written !== false && $written === strlen($bytes)) {
                try {
                    $result = (new PhpCodeScanner())->scan($tmp);
                } catch (\Throwable) {
                    $result = null;
                } finally {
                    @unlink($tmp);
                }
                if (is_array($result) && ($result['safe'] ?? true) === false) {
                    $threats = $result['threats'] ?? [];

                    return $threats === [] ? 'code opener detected' : (string) $threats[0];
                }

                return null;
            }
            @unlink($tmp);
        }

        // Fallback: replicate PhpCodeScanner's opener regexes inline (fail-closed
        // path when no temp file is available).
        if (preg_match('/<\?php\b/i', $bytes)
            || preg_match('/<\?=\s*[\w$\'"(\[\-+!.@]/', $bytes)
            || preg_match('/<\?(?!php\b|xml\b|xpacket\b|=)[\s\w$\/#\'"(\[\-+!.@]/i', $bytes)
            || preg_match('/<%[=@\s]/', $bytes)
            || preg_match('/<script\b[^>]*language\s*=\s*["\']?php/i', $bytes)
            || preg_match('/__halt_compiler\s*\(/i', $bytes)
        ) {
            return 'code opener detected';
        }

        return null;
    }

    private function display(string $name): string
    {
        return SecurityLogger::sanitizeString($name);
    }

    /**
     * @return array{safe: bool, threats: array<string>}
     */
    private function result(bool $safe, array $threats): array
    {
        return ['safe' => $safe, 'threats' => array_values(array_unique($threats))];
    }

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
