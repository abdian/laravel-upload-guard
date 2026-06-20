<?php

namespace Abdian\UploadGuard;

use Abdian\UploadGuard\Concerns\ValidatesFileAccess;
use Illuminate\Http\UploadedFile;

/**
 * PhpCodeScanner — detects PHP/script code in uploads.
 *
 * Design (fail-closed, always-on):
 *   - Opener detection runs over the FULL bytes of EVERY upload regardless of
 *     detected type. There is no "binary => skip" early-exit and no
 *     octet-stream allowlist; a valid image/PDF/zip header never exempts a file.
 *   - The dangerous-function/keyword layer only triggers INSIDE an actual PHP
 *     open-tag region, so benign .js/.py/.csv/.md/.sql files that merely mention
 *     eval/system/exec are not rejected.
 *   - When deep analysis is enabled, PHP regions are tokenized with
 *     token_get_all() (bounded) to catch variable functions / dynamic dispatch /
 *     backtick exec rather than relying on literal substring matching.
 */
class PhpCodeScanner
{
    use ValidatesFileAccess;

    /** Default dangerous functions (also the base for strict mode). */
    protected array $defaultFunctions = [
        'eval', 'assert', 'create_function',
        'call_user_func', 'call_user_func_array',
        'exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec',
        'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'convert_uudecode',
        'include', 'include_once', 'require', 'require_once',
        'extract', 'parse_str', 'preg_replace', 'mb_ereg_replace',
        'move_uploaded_file',
    ];

    /** Extra functions added on top of the default set in strict mode. */
    protected array $strictExtraFunctions = [
        'file_put_contents', 'file_get_contents', 'fopen', 'fwrite', 'fputs',
        'copy', 'rename', 'unlink', 'chmod', 'chown', 'chgrp',
        'curl_exec', 'fsockopen', 'stream_socket_client', 'dl', 'putenv', 'ini_set',
    ];

    protected array $suspiciousPatterns = [
        '/<script[^>]*language\s*=\s*["\']?php["\']?[^>]*>/i',
        '/\bc99\s*shell\b/i',
        '/\br57\s*shell\b/i',
        '/\bb374k\b/i',
        '/\bwso\s*shell\b/i',
        '/\bFilesMan\b/i',
        '/eval\s*\(\s*base64_decode/i',
        '/eval\s*\(\s*gzinflate/i',
        '/assert\s*\(\s*base64_decode/i',
        '/preg_replace\s*\([^)]*\/[a-z]*e[a-z]*["\'\)]/i',
        '/\\\\x3c\\\\x3f/i', // \x3c\x3f = <?
    ];

    /**
     * @return array{safe: bool, threats: array<string>}
     */
    public function scan(UploadedFile|string $file): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;

        if ($path === false || $path === '' || ! is_file($path) || ! is_readable($path)) {
            return ['safe' => false, 'threats' => ['File cannot be read']];
        }

        if (! $this->validateFileAccess($path)) {
            return ['safe' => false, 'threats' => [$this->getFileAccessFailureReason($path)]];
        }

        $content = $this->readContent($path);
        if ($content === null) {
            return ['safe' => false, 'threats' => ['Failed to read file content']];
        }

        $threats = [];

        // 1. Opener detection — ALWAYS, over the full content.
        $threats = array_merge($threats, $this->scanForOpeners($content));

        // 2. Suspicious-pattern detection (web-shell signatures, encoded tags).
        $threats = array_merge($threats, $this->scanForPatterns($content));

        // 3. Dangerous-function layer — only inside actual PHP regions.
        if ($this->getConfig('safeguard.php_scanning.enabled', true)) {
            $regions = $this->extractPhpRegions($content);
            if ($regions !== []) {
                $functions = $this->buildFunctionsList();
                foreach ($regions as $region) {
                    $threats = array_merge($threats, $this->scanRegionForFunctions($region, $functions));
                }
            }
        }

        $threats = array_values(array_unique($threats));

        return ['safe' => $threats === [], 'threats' => $threats];
    }

    private function readContent(string $path): ?string
    {
        $max = (int) $this->getConfig('safeguard.max_scan_size', 25 * 1024 * 1024);
        $max = $max > 0 ? $max : PHP_INT_MAX;

        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }
        // Read one byte past the cap so callers/oversize handling stay bounded.
        $content = stream_get_contents($handle, $max);
        fclose($handle);

        return $content === false ? null : $content;
    }

    /**
     * @return array<string>
     */
    protected function scanForOpeners(string $content): array
    {
        $threats = [];

        if (preg_match('/<\?php\b/i', $content)) {
            $threats[] = 'PHP opening tag (<?php) detected';
        }
        // Short echo tag, requiring a plausible PHP follow char to avoid matching
        // incidental "<?=" byte triples in large binaries.
        if (preg_match('/<\?=\s*[\w$\'"(\[\-+!.@]/', $content)) {
            $threats[] = 'PHP short echo tag (<?=) detected';
        }
        // Bare short tag: "<?" directly followed by ANYTHING that is not one of
        // the XML/XMP processing instructions. With short_open_tag enabled,
        // "<?$x=...", "<?system(...)", "<?{}system(...)", "<?;...", "<?\t" and
        // "<? ..." are all valid executable PHP, so we do NOT constrain the
        // following character. We deliberately exclude only the XML/XMP
        // processing instructions <?xml and <?xpacket (metadata false positives)
        // and the dedicated <?php / <?= cases handled above (duplicate messages).
        if (preg_match('/<\?(?!php\b|xml\b|xpacket\b)/i', $content)) {
            $threats[] = 'PHP short tag (<?) detected';
        }
        // ASP/JSP-style tag: "<%" followed by a plausible script token — "=", "@",
        // whitespace, a letter (e.g. <%eval, <%Runtime, <%out), "!" (<%!), a quote
        // or "(". Broad enough to catch letter-after-<% bypasses while still
        // avoiding incidental "<%" byte pairs in binary content.
        if (preg_match('/<%[\w=@!\s\'"(-]/', $content)) {
            $threats[] = 'ASP-style tag (<%) detected';
        }
        if (preg_match('/<script\b[^>]*language\s*=\s*["\']?php/i', $content)) {
            $threats[] = 'PHP script tag (<script language="php">) detected';
        }
        if (preg_match('/__halt_compiler\s*\(/i', $content)) {
            $threats[] = '__halt_compiler() detected';
        }

        return $threats;
    }

    /**
     * @return array<string>
     */
    protected function scanForPatterns(string $content): array
    {
        $threats = [];
        $patterns = $this->buildPatternsList();
        foreach ($patterns as $pattern) {
            if (! is_string($pattern)) {
                continue;
            }
            if (@preg_match($pattern, $content) === 1) {
                $threats[] = 'Suspicious code pattern detected';
                break;
            }
        }

        return $threats;
    }

    /**
     * Extract the text of each PHP open-tag region (between an opener and ?>/EOF).
     *
     * @return array<string>
     */
    protected function extractPhpRegions(string $content): array
    {
        $regions = [];
        $length = strlen($content);
        $offset = 0;

        while ($offset < $length) {
            if (! preg_match('/<\?php\b|<\?=|<\?(?!php\b|xml\b|xpacket\b)/i', $content, $m, PREG_OFFSET_CAPTURE, $offset)) {
                break;
            }
            $start = $m[0][1];
            $closePos = strpos($content, '?>', $start);
            if ($closePos === false) {
                $regions[] = substr($content, $start);
                break;
            }
            $regions[] = substr($content, $start, $closePos - $start + 2);
            $offset = $closePos + 2;
        }

        return $regions;
    }

    /**
     * @param  array<string>  $functions
     * @return array<string>
     */
    protected function scanRegionForFunctions(string $region, array $functions): array
    {
        if ($this->getConfig('safeguard.php_scanning.deep_analysis', true) && function_exists('token_get_all')) {
            return $this->scanRegionWithTokens($region, $functions);
        }

        return $this->scanRegionWithRegex($region, $functions);
    }

    /**
     * @param  array<string>  $functions
     * @return array<string>
     */
    protected function scanRegionWithTokens(string $region, array $functions): array
    {
        $threats = [];
        $needle = array_flip(array_map('strtolower', $functions));

        // Ensure the region begins with a real opener so the tokenizer enters PHP.
        if (! preg_match('/^<\?(php\b|=|\s)/i', $region)) {
            $region = "<?php \n" . $region;
        }

        $tokens = @token_get_all($region);
        if (! is_array($tokens)) {
            return $this->scanRegionWithRegex($region, $functions);
        }

        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            // Backtick shell execution.
            if ($token === '`') {
                $threats[] = 'Backtick shell execution detected';
                continue;
            }

            if (! is_array($token)) {
                continue;
            }

            [$id, $text] = $token;

            // Direct dangerous function call: T_STRING "name" followed by "(".
            if ($id === T_STRING && isset($needle[strtolower($text)])) {
                if ($this->nextSignificantIsParen($tokens, $i)) {
                    $threats[] = "Dangerous function detected: {$text}()";
                }
                continue;
            }

            // eval / include / require are language constructs (own token ids).
            if (in_array($id, [T_EVAL, T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE], true)) {
                $threats[] = 'Dangerous construct detected: ' . trim($text);
                continue;
            }

            // Variable function dispatch: T_VARIABLE followed by "(".
            if ($id === T_VARIABLE && $this->nextSignificantIsParen($tokens, $i)) {
                $threats[] = 'Dynamic dispatch via variable function detected';
            }
        }

        return array_values(array_unique($threats));
    }

    /**
     * @param  array<int, mixed>  $tokens
     */
    private function nextSignificantIsParen(array $tokens, int $i): bool
    {
        $count = count($tokens);
        for ($j = $i + 1; $j < $count; $j++) {
            $t = $tokens[$j];
            if (is_array($t)) {
                if (in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                return false;
            }

            return $t === '(';
        }

        return false;
    }

    /**
     * @param  array<string>  $functions
     * @return array<string>
     */
    protected function scanRegionWithRegex(string $region, array $functions): array
    {
        $threats = [];
        foreach ($functions as $function) {
            $pattern = '/\b' . preg_quote($function, '/') . '\s*\(/i';
            if (preg_match($pattern, $region)) {
                $threats[] = "Dangerous function detected: {$function}()";
            }
        }
        if (preg_match('/`[^`]+`/', $region)) {
            $threats[] = 'Backtick shell execution detected';
        }

        return array_values(array_unique($threats));
    }

    /**
     * @return array<string>
     */
    protected function buildFunctionsList(): array
    {
        $mode = (string) $this->getConfig('safeguard.php_scanning.mode', 'default');
        $custom = (array) $this->getConfig('safeguard.php_scanning.custom_dangerous_functions', []);
        $exclude = (array) $this->getConfig('safeguard.php_scanning.exclude_functions', []);

        switch ($mode) {
            case 'strict':
                // strict is a SUPERSET of default.
                $functions = array_merge($this->defaultFunctions, $this->strictExtraFunctions, $custom);
                break;

            case 'custom':
                $scan = (array) $this->getConfig('safeguard.php_scanning.scan_functions', []);
                if ($scan === []) {
                    // Do not silently scan for nothing — warn and fall back to default.
                    $this->warnConfig('php_scanning.mode is "custom" but scan_functions is empty; falling back to the default set.');
                    $functions = array_merge($this->defaultFunctions, $custom);
                } else {
                    $functions = array_merge($scan, $custom);
                }
                break;

            case 'default':
            default:
                $functions = array_merge($this->defaultFunctions, $custom);
                break;
        }

        $functions = array_diff($functions, $exclude);

        return array_values(array_unique($functions));
    }

    /**
     * @return array<string>
     */
    protected function buildPatternsList(): array
    {
        $custom = (array) $this->getConfig('safeguard.php_scanning.custom_patterns', []);
        $exclude = (array) $this->getConfig('safeguard.php_scanning.exclude_patterns', []);

        $patterns = $this->suspiciousPatterns;
        foreach ($custom as $pattern) {
            // Validate user-supplied regex at load time (no @-suppression silently
            // hiding broken patterns at scan time).
            if (is_string($pattern) && @preg_match($pattern, '') !== false) {
                $patterns[] = $pattern;
            } else {
                $this->warnConfig('Invalid custom PHP scan pattern ignored.');
            }
        }

        foreach ($exclude as $pattern) {
            $key = array_search($pattern, $patterns, true);
            if ($key !== false) {
                unset($patterns[$key]);
            }
        }

        return array_values($patterns);
    }

    public function containsPhpCode(UploadedFile|string $file): bool
    {
        $result = $this->scan($file);

        return $result['safe'] === false;
    }

    private function warnConfig(string $message): void
    {
        try {
            if (function_exists('logger')) {
                logger()->warning('[safeguard] ' . $message);
            }
        } catch (\Throwable) {
            // ignore
        }
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
