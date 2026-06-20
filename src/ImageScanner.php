<?php

namespace Abdian\UploadGuard;

use Abdian\UploadGuard\Concerns\ValidatesFileAccess;
use Illuminate\Http\UploadedFile;

/**
 * ImageScanner — fail-closed inspection of raster image uploads.
 *
 *   - A decompression-bomb guard reads dimensions/byte size from the HEADER and
 *     rejects oversize images BEFORE any decode (no pixel buffer is allocated).
 *   - All EXIF/IFD sections and the COMMENT data are scanned for embedded code,
 *     and the full PHP byte-scanner runs over the image content. Missing ext-exif
 *     degrades gracefully (skip EXIF, still scan bytes) — never reject all images.
 *   - Trailing data is detected structurally (no fixed threshold; robust GIF
 *     trailer handling).
 *   - An optional re-encode mode rewrites the image to a clean file, destroying
 *     appended/segment payloads. If requested without a backend, it fails loudly.
 */
class ImageScanner
{
    use ValidatesFileAccess;

    /**
     * @return array{safe: bool, threats: array<string>, has_gps: bool, trailing_data: bool}
     */
    public function scan(UploadedFile|string $file): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if ($path === false || $path === '' || ! is_file($path) || ! is_readable($path)) {
            return $this->result(false, ['File cannot be read']);
        }
        if (! $this->validateFileAccess($path)) {
            return $this->result(false, [$this->getFileAccessFailureReason($path)]);
        }

        $threats = [];

        // 1. Decompression-bomb guard — header only, BEFORE any decode.
        $dims = @getimagesize($path); // header-only; does not allocate pixels
        $bombThreat = $this->bombGuard($path, $dims);
        if ($bombThreat !== null) {
            return $this->result(false, [$bombThreat], false, false);
        }

        // 2. Byte scan for code (independent of ext-exif).
        $phpResult = (new PhpCodeScanner())->scan($path);
        if (! $phpResult['safe']) {
            $threats = array_merge($threats, $phpResult['threats']);
        }

        // 3. EXIF / metadata scan (skipped without ext-exif, never fatal).
        $hasGps = false;
        if (function_exists('exif_read_data')) {
            [$metaThreats, $hasGps] = $this->scanExif($path);
            $threats = array_merge($threats, $metaThreats);
        }

        // 4. Structural trailing-data detection.
        $trailing = $this->hasTrailingData($path, $dims === false ? null : (int) $dims[2]);
        if ($trailing) {
            $threats[] = 'Trailing data detected after image end-of-image marker';
        }

        // 5. Content-sniffing polyglot heuristic — a valid image container that
        //    also carries HTML/script markers can be served as XSS regardless of
        //    where the markers sit structurally. Fail closed on any such marker.
        if ($this->hasHtmlScriptMarkers($path)) {
            $threats[] = 'HTML/script markers found in image content (content-sniffing polyglot)';
        }

        $threats = array_values(array_unique($threats));

        return [
            'safe' => $threats === [],
            'threats' => $threats,
            'has_gps' => $hasGps,
            'trailing_data' => $trailing,
        ];
    }

    /**
     * Decompression-bomb guard — inspects the HEADER (byte size + declared
     * dimensions) and rejects oversize images BEFORE any pixel decode allocates
     * memory. Returns a threat message when the guard trips, or null when safe.
     *
     * Self-contained so any decode path (scan, reencode) can run it first and
     * never trust the caller to have validated dimensions.
     *
     * @param  array<mixed>|false  $dims  result of getimagesize(), or false
     */
    private function bombGuard(string $path, array|false $dims): ?string
    {
        $bytes = @filesize($path) ?: 0;
        $maxBytes = (int) $this->getConfig('safeguard.image_scanning.max_bytes', 20 * 1024 * 1024);
        if ($maxBytes > 0 && $bytes > $maxBytes) {
            return "Image exceeds maximum byte size ({$bytes} > {$maxBytes})";
        }

        $headerDims = $dims !== false ? [(int) $dims[0], (int) $dims[1]] : $this->headerDimensions($path);
        $maxPixels = (int) $this->getConfig('safeguard.image_scanning.max_pixels', 64_000_000);
        if ($headerDims !== null) {
            $pixels = $headerDims[0] * $headerDims[1];
            if ($maxPixels > 0 && $pixels > $maxPixels) {
                return "Image dimensions exceed pixel cap ({$headerDims[0]}x{$headerDims[1]})";
            }

            return null;
        }

        // Fail closed: the file structurally claims to be an image (a known
        // container signature) but no parser could determine its dimensions.
        // A bomb that hides its size from every decoder must be treated as
        // over-cap rather than silently skipped.
        if ($maxPixels > 0 && $this->looksLikeImage($path)) {
            return 'Image dimensions could not be determined (failing closed)';
        }

        return null;
    }

    /**
     * Cheap signature check: does the file claim to be a raster image we should
     * have been able to size? Used to fail closed when no dimension parser
     * (getimagesize or headerDimensions) could read the geometry.
     */
    private function looksLikeImage(string $path): bool
    {
        $head = @file_get_contents($path, false, null, 0, 12);
        if ($head === false || strlen($head) < 4) {
            return false;
        }

        return str_starts_with($head, "\x89PNG\r\n\x1a\n")
            || str_starts_with($head, 'GIF87a')
            || str_starts_with($head, 'GIF89a')
            || str_starts_with($head, 'BM')
            || str_starts_with($head, "\xFF\xD8\xFF")          // JPEG
            || str_starts_with($head, "II\x2A\x00")            // classic TIFF, little-endian
            || str_starts_with($head, "MM\x00\x2A")            // classic TIFF, big-endian
            || str_starts_with($head, "II\x2B\x00")            // BigTIFF, little-endian
            || str_starts_with($head, "MM\x00\x2B")            // BigTIFF, big-endian
            || str_starts_with($head, 'RIFF');                 // WebP and friends
    }

    /**
     * Read width/height directly from the file header for the bomb guard, used
     * when getimagesize() bails on a truncated/forged header.
     *
     * @return array{0:int,1:int}|null
     */
    private function headerDimensions(string $path): ?array
    {
        $head = @file_get_contents($path, false, null, 0, 16);
        if ($head === false || strlen($head) < 8) {
            return null;
        }

        // TIFF/BigTIFF: getimagesize() often returns false for these (and always
        // for BigTIFF), so the bomb guard would never run. Parse the IFD here.
        if (str_starts_with($head, "II\x2A\x00") || str_starts_with($head, "MM\x00\x2A")
            || str_starts_with($head, "II\x2B\x00") || str_starts_with($head, "MM\x00\x2B")) {
            return $this->tiffDimensions($path, $head);
        }

        if (strlen($head) < 24) {
            return null;
        }

        // PNG: IHDR width/height are big-endian 32-bit at offsets 16 and 20.
        if (str_starts_with($head, "\x89PNG\r\n\x1a\n")) {
            $w = unpack('N', substr($head, 16, 4))[1] ?? 0;
            $h = unpack('N', substr($head, 20, 4))[1] ?? 0;

            return [(int) $w, (int) $h];
        }
        // GIF: width/height are little-endian 16-bit at offsets 6 and 8.
        if (str_starts_with($head, 'GIF87a') || str_starts_with($head, 'GIF89a')) {
            $w = unpack('v', substr($head, 6, 2))[1] ?? 0;
            $h = unpack('v', substr($head, 8, 2))[1] ?? 0;

            return [(int) $w, (int) $h];
        }
        // BMP: width/height little-endian 32-bit at offsets 18 and 22 (BITMAPINFOHEADER).
        if (str_starts_with($head, 'BM')) {
            $w = unpack('V', substr($head, 18, 4))[1] ?? 0;
            $h = unpack('V', substr($head, 22, 4))[1] ?? 0;

            return [(int) $w, (int) $h];
        }

        return null;
    }

    /**
     * Parse ImageWidth (tag 0x0100) and ImageLength (tag 0x0101) from a TIFF or
     * BigTIFF first IFD. Endianness is read from the header; BigTIFF ('+'/0x2B)
     * uses 8-byte offsets and counts, classic TIFF ('*'/0x2A) uses 2/4-byte.
     * Returns null only when nothing can be read — callers fail closed on that.
     *
     * @return array{0:int,1:int}|null
     */
    private function tiffDimensions(string $path, string $head): ?array
    {
        $little = $head[0] === 'I';
        $big = ord($head[3]) === 0x2B || ord($head[2]) === 0x2B; // BigTIFF magic 43

        // Read enough of the file to cover the first IFD entries.
        $buf = @file_get_contents($path, false, null, 0, 65536);
        if ($buf === false || strlen($buf) < 16) {
            return null;
        }

        if ($big) {
            // bytes 8..15: 8-byte offset of first IFD.
            $ifdOffset = $this->tiffUInt($buf, 8, 8, $little);
            if ($ifdOffset === null || $ifdOffset < 0 || $ifdOffset + 8 > strlen($buf)) {
                return null;
            }
            $count = $this->tiffUInt($buf, $ifdOffset, 8, $little);
            $entryStart = $ifdOffset + 8;
            $entrySize = 20;
            $countSize = 8;
            $valueOffset = 12; // tag(2)+type(2)+count(8)
        } else {
            // bytes 4..7: 4-byte offset of first IFD.
            $ifdOffset = $this->tiffUInt($buf, 4, 4, $little);
            if ($ifdOffset === null || $ifdOffset < 0 || $ifdOffset + 2 > strlen($buf)) {
                return null;
            }
            $count = $this->tiffUInt($buf, $ifdOffset, 2, $little);
            $entryStart = $ifdOffset + 2;
            $entrySize = 12;
            $countSize = 2;
            $valueOffset = 8; // tag(2)+type(2)+count(4)
        }

        if ($count === null || $count <= 0 || $count > 65535) {
            return null;
        }

        $width = null;
        $height = null;
        for ($i = 0; $i < $count; $i++) {
            $entry = $entryStart + $i * $entrySize;
            if ($entry + $entrySize > strlen($buf)) {
                break;
            }
            $tag = $this->tiffUInt($buf, $entry, 2, $little);
            $type = $this->tiffUInt($buf, $entry + 2, 2, $little);
            if ($tag === null || $type === null || ($tag !== 0x0100 && $tag !== 0x0101)) {
                continue;
            }
            // Field value size by type: 3=SHORT(2),4=LONG(4),16=LONG8(8). The value
            // sits inline (left-justified) in the value field for these sizes.
            $valueSize = match ($type) {
                3 => 2,
                4 => 4,
                16 => 8,
                default => 0,
            };
            if ($valueSize === 0) {
                continue;
            }
            $value = $this->tiffUInt($buf, $entry + $valueOffset, min($valueSize, $entrySize - $valueOffset), $little);
            if ($value === null) {
                continue;
            }
            if ($tag === 0x0100) {
                $width = $value;
            } else {
                $height = $value;
            }
        }

        if ($width === null && $height === null) {
            return null;
        }

        return [(int) ($width ?? 0), (int) ($height ?? 0)];
    }

    /**
     * Read an unsigned integer of $size bytes (1,2,4,8) from $buf at $offset with
     * the given endianness. Returns null when the bytes are out of range.
     */
    private function tiffUInt(string $buf, int $offset, int $size, bool $little): ?int
    {
        if ($offset < 0 || $offset + $size > strlen($buf)) {
            return null;
        }
        $slice = substr($buf, $offset, $size);
        $value = 0;
        if ($little) {
            for ($i = $size - 1; $i >= 0; $i--) {
                $value = ($value << 8) | ord($slice[$i]);
            }
        } else {
            for ($i = 0; $i < $size; $i++) {
                $value = ($value << 8) | ord($slice[$i]);
            }
        }

        return $value;
    }

    /**
     * @return array{0: array<string>, 1: bool} [threats, hasGps]
     */
    private function scanExif(string $path): array
    {
        $threats = [];
        $hasGps = false;

        $exif = @exif_read_data($path, null, true);
        if (! is_array($exif)) {
            return [$threats, false];
        }

        $flat = $this->flatten($exif);
        foreach ($flat as $value) {
            if (! is_string($value)) {
                continue;
            }
            if (preg_match('/<\?php\b|<\?=|<script\b|\beval\s*\(|\bsystem\s*\(|\bbase64_decode\s*\(/i', $value)) {
                $threats[] = 'Suspicious code found in image metadata';
                break;
            }
        }

        if (isset($exif['GPS']) && ! empty($exif['GPS'])) {
            $hasGps = true;
            $checkGps = (bool) $this->getConfig('safeguard.image_scanning.check_gps', true);
            $blockGps = (bool) $this->getConfig('safeguard.image_scanning.block_gps', false);
            if ($checkGps && $blockGps) {
                $threats[] = 'GPS location data present in image metadata';
            }
        }

        return [$threats, $hasGps];
    }

    /**
     * @param  array<mixed>  $data
     * @return array<int, mixed>
     */
    private function flatten(array $data): array
    {
        $out = [];
        array_walk_recursive($data, static function ($value) use (&$out) {
            $out[] = $value;
        });

        return $out;
    }

    /**
     * Detect bytes appended after the format's structural end-of-image.
     */
    private function hasTrailingData(string $path, ?int $type): bool
    {
        $content = @file_get_contents($path, false, null, 0, $this->maxScanSize() + 1);
        if ($content === false || $content === '') {
            return false;
        }

        $result = match ($type) {
            IMAGETYPE_PNG => $this->pngTrailing($content),
            IMAGETYPE_JPEG => $this->jpegTrailing($content),
            IMAGETYPE_GIF => $this->gifTrailing($content),
            IMAGETYPE_BMP => $this->bmpTrailing($content),
            IMAGETYPE_TIFF_II, IMAGETYPE_TIFF_MM => $this->tiffTrailing($content),
            default => false,
        };
        if ($result) {
            return true;
        }

        // getimagesize() can return false (no $type) for BMP/TIFF polyglots, yet
        // the file still structurally claims to be one. Sniff by signature so the
        // trailing check is never skipped just because the decoder bailed.
        if ($type === null) {
            if (str_starts_with($content, 'BM')) {
                return $this->bmpTrailing($content);
            }
            if (str_starts_with($content, "II\x2A\x00") || str_starts_with($content, "MM\x00\x2A")
                || str_starts_with($content, "II\x2B\x00") || str_starts_with($content, "MM\x00\x2B")) {
                return $this->tiffTrailing($content);
            }
        }

        return false;
    }

    /**
     * Compute a BMP's structural end from the DIB header — pixel-data offset
     * (bfOffBits @10) plus the row-padded image byte size derived from
     * width/height/bpp — and flag any bytes beyond it. The bfSize field (@2) is
     * not trusted: some encoders (e.g. GD) write a value that excludes part of
     * the file, so it cannot be used to detect appended payloads reliably.
     */
    private function bmpTrailing(string $content): bool
    {
        $len = strlen($content);
        if ($len < 38 || ! str_starts_with($content, 'BM')) {
            return false;
        }

        $offBits = unpack('V', substr($content, 10, 4))[1] ?? 0;
        $width = unpack('V', substr($content, 18, 4))[1] ?? 0;
        $height = unpack('V', substr($content, 22, 4))[1] ?? 0;
        $bpp = unpack('v', substr($content, 28, 2))[1] ?? 0;

        // Sign-correct the 32-bit height (top-down bitmaps use a negative value).
        if ($height >= 0x80000000) {
            $height -= 0x100000000;
        }
        $height = abs($height);

        if ($offBits <= 0 || $width <= 0 || $height <= 0 || $bpp <= 0) {
            return true; // malformed geometry — fail closed
        }

        $rowSize = intdiv($bpp * $width + 31, 32) * 4; // rows are padded to 4 bytes
        $structuralEnd = $offBits + $rowSize * $height;

        return $len > $structuralEnd;
    }

    /**
     * TIFF has no end-of-image marker, so structural trailing detection is
     * unreliable; the content-sniffing heuristic handles TIFF polyglots. Here we
     * only flag the obvious case of a foreign container appended after the TIFF.
     */
    private function tiffTrailing(string $content): bool
    {
        // A TIFF/ZIP polyglot (e.g. appended "PK\x03\x04") is a clear smuggling
        // vector; flag any well-known archive/document signature riding along.
        foreach (["PK\x03\x04", "PK\x05\x06", "Rar!\x1a\x07", "\x1f\x8b", '%PDF-'] as $sig) {
            if (str_contains(substr($content, 8), $sig)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Cheap content heuristic for content-sniffing XSS polyglots: an otherwise
     * valid image that also contains HTML/script markers can be rendered as
     * markup by a sniffing browser. Scans the raw bytes (capped) case-insensitively.
     */
    private function hasHtmlScriptMarkers(string $path): bool
    {
        $content = @file_get_contents($path, false, null, 0, $this->maxScanSize() + 1);
        if ($content === false || $content === '') {
            return false;
        }

        return (bool) preg_match(
            '/<script\b|<!doctype\s+html|<html\b|<svg\b[^>]*\bon[a-z]+\s*=/i',
            $content
        );
    }

    private function pngTrailing(string $content): bool
    {
        // The IEND chunk is the structural end: length(0) + "IEND" + CRC(4).
        $pos = strpos($content, 'IEND');
        if ($pos === false) {
            return false;
        }
        $structuralEnd = $pos + 4 + 4; // "IEND" + CRC

        return strlen($content) > $structuralEnd;
    }

    private function jpegTrailing(string $content): bool
    {
        // A clean JPEG ends with the EOI marker FFD9.
        $eoi = strrpos($content, "\xFF\xD9");
        if ($eoi === false) {
            return true; // no EOI at all — malformed/appended
        }

        return strlen($content) > $eoi + 2;
    }

    private function gifTrailing(string $content): bool
    {
        // Walk GIF blocks to find the structural trailer (0x3B), then check for
        // any bytes beyond it (robust to a single extra trailer byte).
        $len = strlen($content);
        if ($len < 13 || ! (str_starts_with($content, 'GIF87a') || str_starts_with($content, 'GIF89a'))) {
            return false;
        }

        $pos = 6;
        // Logical Screen Descriptor.
        $packed = ord($content[10]);
        $pos = 13;
        if ($packed & 0x80) {
            $gctSize = 3 * (1 << (($packed & 0x07) + 1));
            $pos += $gctSize;
        }

        while ($pos < $len) {
            $block = ord($content[$pos]);
            if ($block === 0x3B) { // trailer
                return $len > $pos + 1;
            }
            if ($block === 0x2C) { // image descriptor
                $pos += 10;
                if ($pos > $len) {
                    return false;
                }
                $localPacked = ord($content[$pos - 1]);
                if ($localPacked & 0x80) {
                    $pos += 3 * (1 << (($localPacked & 0x07) + 1));
                }
                $pos += 1; // LZW min code size
                $pos = $this->skipSubBlocks($content, $pos);
            } elseif ($block === 0x21) { // extension
                $pos += 2; // 0x21 + label
                $pos = $this->skipSubBlocks($content, $pos);
            } else {
                // Unknown byte where a block was expected — treat as trailing.
                return true;
            }
            if ($pos === -1) {
                return false;
            }
        }

        return false;
    }

    private function skipSubBlocks(string $content, int $pos): int
    {
        $len = strlen($content);
        while ($pos < $len) {
            $size = ord($content[$pos]);
            $pos += 1;
            if ($size === 0) {
                return $pos;
            }
            $pos += $size;
        }

        return -1;
    }

    /**
     * Re-encode an image to a clean file, stripping appended/segment payloads.
     * Returns true on success. Fails (false) loudly if no backend is available.
     */
    public function reencode(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        if ($path === false || ! is_file($path)) {
            return false;
        }

        $dims = @getimagesize($path);
        if ($dims === false) {
            return false;
        }
        $type = (int) $dims[2];

        // Decompression-bomb guard BEFORE any decode, independent of call order:
        // a tiny file declaring huge dimensions must never reach a pixel decoder.
        if ($this->bombGuard($path, $dims) !== null) {
            return false;
        }

        if (function_exists('imagecreatefromstring')) {
            return $this->reencodeWithGd($path, $type);
        }

        // GD unavailable — fall back to Imagick when present.
        if (class_exists('Imagick')) {
            return $this->reencodeWithImagick($path);
        }

        // No backend: do not silently pass through.
        return false;
    }

    private function reencodeWithGd(string $path, int $type): bool
    {
        // Re-run the bomb guard so a direct call to this path cannot decode a
        // forged-dimension file without the header check.
        if ($this->bombGuard($path, @getimagesize($path)) !== null) {
            return false;
        }

        $data = @file_get_contents($path);
        if ($data === false) {
            return false;
        }
        $image = @imagecreatefromstring($data);
        if ($image === false) {
            return false;
        }

        $quality = (int) $this->getConfig('safeguard.image_scanning.reencode_quality', 85);
        $tmp = $path . '.sgtmp';

        $ok = match ($type) {
            IMAGETYPE_JPEG => function_exists('imagejpeg') && imagejpeg($image, $tmp, $quality),
            IMAGETYPE_PNG => function_exists('imagepng') && imagepng($image, $tmp),
            IMAGETYPE_GIF => function_exists('imagegif') && imagegif($image, $tmp),
            IMAGETYPE_WEBP => function_exists('imagewebp') && imagewebp($image, $tmp, $quality),
            IMAGETYPE_BMP => function_exists('imagebmp') && imagebmp($image, $tmp),
            default => false,
        };
        imagedestroy($image);

        if ($ok === false || ! is_file($tmp)) {
            @unlink($tmp);

            return false;
        }

        return @rename($tmp, $path);
    }

    /**
     * Re-encode using ext-imagick when GD is unavailable. Strips all profiles
     * and metadata, then writes a clean file. Guarded behind class_exists so the
     * package never hard-depends on Imagick at parse time.
     */
    private function reencodeWithImagick(string $path): bool
    {
        if (! class_exists('Imagick')) {
            return false;
        }

        // Re-run the bomb guard before reading pixels, mirroring the GD path.
        if ($this->bombGuard($path, @getimagesize($path)) !== null) {
            return false;
        }

        $data = @file_get_contents($path);
        if ($data === false) {
            return false;
        }

        $tmp = $path . '.sgtmp';
        $quality = (int) $this->getConfig('safeguard.image_scanning.reencode_quality', 85);

        try {
            $imagick = new \Imagick();
            $imagick->readImageBlob($data);
            $imagick->stripImage();
            $imagick->setImageCompressionQuality($quality);
            $ok = $imagick->writeImage($tmp);
            $imagick->clear();
            $imagick->destroy();
        } catch (\Throwable) {
            @unlink($tmp);

            return false;
        }

        if ($ok === false || ! is_file($tmp)) {
            @unlink($tmp);

            return false;
        }

        return @rename($tmp, $path);
    }

    public function isImage(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        if ($path === false || ! is_file($path)) {
            return false;
        }

        return @getimagesize($path) !== false;
    }

    /**
     * @return array{safe: bool, threats: array<string>, has_gps: bool, trailing_data: bool}
     */
    private function result(bool $safe, array $threats, bool $hasGps = false, bool $trailing = false): array
    {
        return [
            'safe' => $safe,
            'threats' => array_values(array_unique($threats)),
            'has_gps' => $hasGps,
            'trailing_data' => $trailing,
        ];
    }

    private function maxScanSize(): int
    {
        $max = (int) $this->getConfig('safeguard.max_scan_size', 25 * 1024 * 1024);

        return $max > 0 ? $max : PHP_INT_MAX;
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
