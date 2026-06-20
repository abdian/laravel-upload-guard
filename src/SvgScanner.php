<?php

namespace Abdian\UploadGuard;

use Abdian\UploadGuard\Concerns\ValidatesFileAccess;
use enshrined\svgSanitize\Sanitizer;
use Illuminate\Http\UploadedFile;

/**
 * SvgScanner — allowlist sanitization for SVG uploads.
 *
 * SVG XSS cannot be reliably caught with blocklist regexes (unquoted handlers,
 * encodings, namespaces). This scanner parses the SVG through an allowlist
 * sanitizer (enshrined/svg-sanitize), strips disallowed elements/attributes,
 * dangerous URL schemes, and ALL DTD/DOCTYPE/entities, and makes the cleaned
 * output the version that is stored.
 *
 * Modes:
 *   - 'sanitize' (default): rewrite the file with the cleaned SVG.
 *   - 'reject': reject any SVG that was not already clean.
 *
 * Any XML parsing the package performs installs a denying external-entity
 * loader and parses with LIBXML_NONET to defeat XXE.
 */
class SvgScanner
{
    use ValidatesFileAccess;

    /**
     * @return array{safe: bool, threats: array<string>, modified: bool, clean: ?string}
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

        $content = @file_get_contents($path, false, null, 0, $this->maxScanSize() + 1);
        if ($content === false) {
            return $this->result(false, ['Failed to read file content']);
        }

        // Oversize SVGs are rejected rather than parsed unbounded.
        if (strlen($content) > $this->maxScanSize()) {
            return $this->result(false, ['SVG exceeds maximum scan size']);
        }

        // UTF-16 (BOM FF FE / FE FF) SVGs are mis-detected by an ASCII '<svg'
        // probe and would skip sanitization entirely. Decode to UTF-8 first;
        // if it is BOM-marked UTF-16 but cannot be decoded, fail closed.
        $utf16Threat = false;
        if ($this->hasUtf16Bom($content)) {
            $decoded = $this->decodeUtf16($content);
            if ($decoded === null) {
                return $this->result(false, ['UTF-16 SVG could not be decoded']);
            }
            $content = $decoded;
            $utf16Threat = true;
        }

        if (! $this->looksLikeSvg($content)) {
            // Not actually an SVG; nothing for this scanner to sanitize.
            return $this->result(true, [], false, null);
        }

        $this->hardenLibxml();

        $threats = [];

        if ($utf16Threat) {
            $threats[] = 'UTF-16 encoded SVG decoded for inspection';
        }

        // DTD / DOCTYPE / entity presence is an XXE vector.
        $hadDoctype = (bool) preg_match('/<!DOCTYPE/i', $content) || (bool) preg_match('/<!ENTITY/i', $content);
        if ($hadDoctype) {
            $threats[] = 'DOCTYPE/DTD/entity declaration present (XXE vector)';
        }

        // Remote/dynamic CSS inside <style> survives allowlist sanitization
        // byte-identical (@import, @font-face, url(http(s)/file/protocol-relative),
        // expression()), enabling exfiltration/tracking/clickjacking. Fail closed.
        $cssThreat = $this->detectDangerousStyle($content);
        $hadCssThreat = $cssThreat !== null;
        if ($hadCssThreat) {
            $threats[] = $cssThreat;
        }

        // Local-filesystem / file: / UNC hrefs on <image>/<use> enable local file
        // read; the sanitizer permits any value beginning with '/'. Fail closed.
        $hrefThreat = $this->detectLocalHref($content);
        $hadHrefThreat = $hrefThreat !== null;
        if ($hadHrefThreat) {
            $threats[] = $hrefThreat;
        }

        $sanitizer = $this->makeSanitizer();
        $clean = $sanitizer->sanitize($content);

        if ($clean === false || $clean === '') {
            // Could not be parsed/cleaned — fail closed.
            return $this->result(false, array_merge($threats, ['SVG could not be sanitized']));
        }

        $issues = method_exists($sanitizer, 'getXmlIssues') ? $sanitizer->getXmlIssues() : [];
        foreach ($issues as $issue) {
            $message = is_array($issue) ? ($issue['message'] ?? 'XML issue') : (string) $issue;
            $threats[] = 'Removed: ' . $message;
        }

        $modified = $this->normalize($clean) !== $this->normalize($content);
        if ($modified && $threats === []) {
            $threats[] = 'Disallowed SVG content removed during sanitization';
        }

        // Threats the allowlist sanitizer leaves intact must fail closed
        // regardless of mode, so the orchestrator rejects the upload.
        $hardFail = $hadCssThreat || $hadHrefThreat;

        $mode = (string) $this->getConfig('safeguard.svg_scanning.mode', 'sanitize');

        if ($mode === 'reject') {
            // Reject if the original was not already clean.
            return $this->result(! $modified && ! $hadDoctype && ! $hardFail, $threats, $modified, $clean);
        }

        // sanitize mode: cleaned output is safe to store unless a residual
        // (unsanitizable) threat was detected.
        return $this->result(! $hardFail, $threats, $modified, $clean);
    }

    /**
     * Sanitize an SVG file in place, writing back the cleaned bytes.
     * Returns true when the stored file is clean (or was already clean).
     */
    public function sanitizeFile(UploadedFile|string $file): bool
    {
        $result = $this->scan($file);
        if ($result['clean'] === null) {
            return $result['safe'];
        }

        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        if ($path === false) {
            return false;
        }

        if ($result['modified']) {
            // Crash-safe rewrite.
            $tmp = $path . '.sgtmp';
            if (@file_put_contents($tmp, $result['clean']) === false || @rename($tmp, $path) === false) {
                @unlink($tmp);

                return false;
            }
        }

        return true;
    }

    private function makeSanitizer(): Sanitizer
    {
        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences((bool) $this->getConfig('safeguard.svg_scanning.remove_remote_references', true));

        $allowedTags = (array) $this->getConfig('safeguard.svg_scanning.allowed_tags', []);
        if ($allowedTags !== []) {
            \Abdian\UploadGuard\Support\SvgAllowedTags::$tags = array_values(array_map('strval', $allowedTags));
            $sanitizer->setAllowedTags(new \Abdian\UploadGuard\Support\SvgAllowedTags());
        }

        $allowedAttrs = (array) $this->getConfig('safeguard.svg_scanning.allowed_attributes', []);
        if ($allowedAttrs !== []) {
            \Abdian\UploadGuard\Support\SvgAllowedAttributes::$attributes = array_values(array_map('strval', $allowedAttrs));
            $sanitizer->setAllowedAttrs(new \Abdian\UploadGuard\Support\SvgAllowedAttributes());
        }

        return $sanitizer;
    }

    private function looksLikeSvg(string $content): bool
    {
        return (bool) preg_match('/<svg\b/i', $content);
    }

    /**
     * True when the byte stream starts with a UTF-16 BOM (FF FE or FE FF).
     */
    private function hasUtf16Bom(string $content): bool
    {
        return str_starts_with($content, "\xFF\xFE") || str_starts_with($content, "\xFE\xFF");
    }

    /**
     * Decode a BOM-marked UTF-16 byte stream to UTF-8, or null on failure.
     */
    private function decodeUtf16(string $content): ?string
    {
        $encoding = str_starts_with($content, "\xFF\xFE") ? 'UTF-16LE' : 'UTF-16BE';
        $body = substr($content, 2);

        if (function_exists('mb_convert_encoding')) {
            $decoded = @mb_convert_encoding($body, 'UTF-8', $encoding);
            if (is_string($decoded) && $decoded !== '') {
                return $decoded;
            }
        }

        if (function_exists('iconv')) {
            $decoded = @iconv($encoding, 'UTF-8//IGNORE', $body);
            if (is_string($decoded) && $decoded !== '') {
                return $decoded;
            }
        }

        return null;
    }

    /**
     * Inspect <style> blocks for remote/dynamic CSS references that the
     * allowlist sanitizer cannot strip. Returns a threat message or null.
     */
    private function detectDangerousStyle(string $content): ?string
    {
        if (! preg_match_all('/<style\b[^>]*>(.*?)<\/style\s*>/is', $content, $matches)) {
            return null;
        }

        foreach ($matches[1] as $css) {
            if (preg_match('/@import\b/i', $css)) {
                return 'Remote/dynamic CSS in <style> (@import)';
            }
            if (preg_match('/@font-face\b/i', $css)) {
                return 'Remote/dynamic CSS in <style> (@font-face)';
            }
            if (preg_match('/expression\s*\(/i', $css)) {
                return 'Dynamic CSS expression() in <style>';
            }
            // url(...) pointing at a remote/local-file/protocol-relative target.
            if (preg_match('/url\s*\(\s*["\']?\s*(?:https?:|file:|\/\/)/i', $css)) {
                return 'Remote/dynamic CSS url() reference in <style>';
            }
        }

        return null;
    }

    /**
     * Detect href/xlink:href values that read the local filesystem
     * (absolute path, file: scheme, or UNC). data: and #fragment refs are
     * still allowed. Returns a threat message or null.
     */
    private function detectLocalHref(string $content): ?string
    {
        if (! preg_match_all('/\b(?:xlink:href|href)\s*=\s*(["\'])(.*?)\1/is', $content, $matches)) {
            return null;
        }

        foreach ($matches[2] as $href) {
            $value = trim(html_entity_decode($href, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            if ($value === '') {
                continue;
            }

            // Same-document fragments and data URIs remain allowed.
            if ($value[0] === '#' || preg_match('/^data:/i', $value)) {
                continue;
            }

            // file: scheme.
            if (preg_match('/^file:/i', $value)) {
                return 'Local-filesystem href (file: scheme)';
            }

            // UNC path (\\host\share).
            if (str_starts_with($value, '\\\\')) {
                return 'Local-filesystem href (UNC path)';
            }

            // Absolute filesystem path, but NOT a protocol-relative '//host' URL.
            if ($value[0] === '/' && ! str_starts_with($value, '//')) {
                return 'Local-filesystem href (absolute path)';
            }
        }

        return null;
    }

    private function hardenLibxml(): void
    {
        if (function_exists('libxml_set_external_entity_loader')) {
            libxml_set_external_entity_loader(static fn () => null);
        }
        // PHP < 8 needs this explicitly; harmless (deprecated no-op) on PHP 8+.
        if (PHP_VERSION_ID < 80000 && function_exists('libxml_disable_entity_loader')) {
            libxml_disable_entity_loader(true);
        }
    }

    private function normalize(string $svg): string
    {
        return preg_replace('/\s+/', ' ', trim($svg)) ?? $svg;
    }

    /**
     * @return array{safe: bool, threats: array<string>, modified: bool, clean: ?string}
     */
    private function result(bool $safe, array $threats, bool $modified = false, ?string $clean = null): array
    {
        return [
            'safe' => $safe,
            'threats' => array_values(array_unique($threats)),
            'modified' => $modified,
            'clean' => $clean,
        ];
    }

    private function maxScanSize(): int
    {
        $max = (int) $this->getConfig('safeguard.max_scan_size', 25 * 1024 * 1024);

        return $max > 0 ? $max : PHP_INT_MAX;
    }

    public function isSvg(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        if ($path === false || ! is_file($path)) {
            return false;
        }
        $head = @file_get_contents($path, false, null, 0, 1024);

        return $head !== false && $this->looksLikeSvg($head);
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
