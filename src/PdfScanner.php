<?php

namespace Abdian\UploadGuard;

use Abdian\UploadGuard\Concerns\ValidatesFileAccess;
use Illuminate\Http\UploadedFile;
use Smalot\PdfParser\Parser as PdfParser;

/**
 * PdfScanner — decodes PDFs before scanning for dangerous content.
 *
 * Detection backbone (always runs, even when the parser library is absent):
 *   - inflate FlateDecode / ASCIIHexDecode / ASCII85Decode / LZWDecode streams
 *     (this also surfaces /ObjStm object-stream contents);
 *   - decode #xx name escapes;
 *   - match dangerous PDF names ANCHORED on PDF delimiters and case-sensitively
 *     so incidental substrings (javascript.info, /Sounds, /Movies) don't trip.
 *
 * smalot/pdfparser, when available, additionally provides authoritative page
 * counts and decrypted object access.
 */
class PdfScanner
{
    use ValidatesFileAccess;

    /** Dangerous PDF name objects (case-sensitive, delimiter-anchored). */
    protected array $dangerousNames = [
        '/JavaScript', '/JS', '/Launch', '/OpenAction', '/AA',
        '/SubmitForm', '/ImportData', '/GoToR', '/GoToE',
        '/RichMedia', '/EmbeddedFile', '/FileAttachment',
    ];

    protected array $suspiciousJsFunctions = [
        'app.alert', 'app.launchURL', 'app.openDoc', 'app.execMenuItem',
        'util.printf', 'getURL', 'submitForm', 'exportDataObject',
        'this.exportDataObject', 'this.submitForm', 'eval(', 'unescape(',
        'String.fromCharCode',
    ];

    /**
     * @return array{safe: bool, threats: array<string>, has_javascript: bool, has_external_links: bool}
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
        if (! str_starts_with($content, '%PDF-')) {
            return $this->result(false, ['Not a valid PDF file']);
        }
        if (strlen($content) > $this->maxScanSize()) {
            return $this->result(false, ['PDF exceeds maximum scan size']);
        }

        $threats = [];
        $hasJs = false;

        // Encrypted PDF handling (no ">1 /Encrypt" heuristic).
        $encrypted = (bool) preg_match('/\/Encrypt\b/', $content);

        // Build the searchable surface: raw + inflated streams, with #xx decoded.
        $decoded = $this->decodeStreams($content);

        // Authoritative second source: when smalot/pdfparser is available, also
        // enumerate decoded objects through it and append their serialized/text
        // form. This covers indirect-filter / object-stream cases the regex
        // extractor may miss. A parse failure must NOT reduce coverage, so the
        // regex surface above always stands on its own (fail-closed).
        $parserSurface = $this->parserObjectSurface($path);

        $surface = $this->decodeHexNames($content . "\n" . $decoded . "\n" . $parserSurface);

        // Anchored, case-sensitive dangerous-name matching.
        $actions = $this->activeNames();
        foreach ($actions as $name) {
            if ($this->matchesName($surface, $name)) {
                $threats[] = 'Dangerous PDF action detected: ' . ltrim($name, '/');
                if ($name === '/JavaScript' || $name === '/JS') {
                    $hasJs = true;
                }
            }
        }

        if ($hasJs) {
            foreach ($this->suspiciousJsFunctions as $fn) {
                if (str_contains($surface, $fn)) {
                    $threats[] = "Suspicious JavaScript function detected: {$fn}";
                }
            }
        }

        // Dangerous URL schemes (anchored to avoid matching plain links).
        foreach (['javascript:', 'vbscript:'] as $scheme) {
            if (stripos($surface, $scheme) !== false) {
                $threats[] = "Dangerous URL scheme detected: {$scheme}";
            }
        }

        $hasExternalLinks = (bool) preg_match('/\/URI\s*\(/', $surface);

        // If encrypted, ensure we could actually inspect it; otherwise fail closed.
        if ($encrypted) {
            $inspectable = $decoded !== '' || $this->parserCanRead($path);
            if (! $inspectable) {
                $policy = (string) $this->getConfig('safeguard.pdf_scanning.encrypted_policy', 'reject');
                if ($policy !== 'allow') {
                    $threats[] = 'Encrypted PDF could not be inspected';
                }
            }
        }

        $threats = array_values(array_unique($threats));

        return [
            'safe' => $threats === [],
            'threats' => $threats,
            'has_javascript' => $hasJs,
            'has_external_links' => $hasExternalLinks,
        ];
    }

    /**
     * Authoritative page count, or null when it cannot be determined.
     */
    public function pageCount(UploadedFile|string $file): ?int
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        if ($path === false || ! is_file($path)) {
            return null;
        }

        // Prefer the parser (handles compressed page trees / ObjStm), but never
        // hand it an oversized file — fall back to the bounded structural count.
        $size = @filesize($path);
        $withinBudget = $size !== false && $size <= $this->maxScanSize();

        if ($withinBudget && class_exists(PdfParser::class)) {
            try {
                $parser = new PdfParser();
                $document = $parser->parseFile($path);
                $pages = $document->getPages();

                return count($pages) > 0 ? count($pages) : null;
            } catch (\Throwable) {
                // fall through to structural counting
            }
        }

        return $this->structuralPageCount($path);
    }

    private function structuralPageCount(string $path): ?int
    {
        $content = @file_get_contents($path, false, null, 0, $this->maxScanSize() + 1);
        if ($content === false) {
            return null;
        }
        $surface = $content . "\n" . $this->decodeStreams($content);

        // Strip PDF comments (lines beginning with %) so injected "% /Type /Page"
        // tokens cannot inflate the count.
        $surface = preg_replace('/^[ \t]*%[^\r\n]*/m', '', $surface) ?? $surface;

        // Authoritative: the /Count of the root /Pages node.
        if (preg_match_all('/\/Type\s*\/Pages\b[^>]*?\/Count\s+(\d+)/s', $surface, $m)) {
            return max(array_map('intval', $m[1]));
        }
        if (preg_match_all('/\/Count\s+(\d+)[^>]*?\/Type\s*\/Pages\b/s', $surface, $m)) {
            return max(array_map('intval', $m[1]));
        }

        return null;
    }

    /**
     * Enumerate decoded objects through smalot/pdfparser and return their
     * serialized text as an extra scan surface. Returns '' when the parser is
     * unavailable, the file is over budget, or parsing throws — callers always
     * keep the regex surface, so coverage never drops (fail-closed).
     */
    private function parserObjectSurface(string $path): string
    {
        if (! class_exists(PdfParser::class)) {
            return '';
        }
        // Bound work: never hand an oversized file to the parser.
        $size = @filesize($path);
        if ($size === false || $size > $this->maxScanSize()) {
            return '';
        }

        try {
            $parser = new PdfParser();
            $document = $parser->parseFile($path);

            $out = '';
            foreach ($document->getObjects() as $object) {
                // Header (dict/details) carries /JavaScript, /Launch, etc.
                try {
                    $details = $object->getDetails();
                    if ($details !== []) {
                        $out .= "\n" . $this->flattenDetails($details);
                    }
                } catch (\Throwable) {
                    // ignore a single object's header failure
                }
                // Decoded content (e.g. JS bodies, object-stream payloads).
                try {
                    $content = $object->getContent();
                    if (is_string($content) && $content !== '') {
                        $out .= "\n" . $content;
                    }
                } catch (\Throwable) {
                    // ignore a single object's content failure
                }
                if (strlen($out) > $this->maxScanSize()) {
                    break;
                }
            }

            return $out;
        } catch (\Throwable) {
            return '';
        }
    }

    /**
     * Flatten a smalot details array into a /Name-prefixed token string so the
     * anchored dangerous-name matcher can see keys like "JavaScript" / "Launch".
     *
     * @param  array<mixed>  $details
     */
    private function flattenDetails(array $details): string
    {
        $out = '';
        foreach ($details as $key => $value) {
            if (is_string($key)) {
                $out .= ' /' . $key;
            }
            if (is_array($value)) {
                $out .= ' ' . $this->flattenDetails($value);
            } elseif (is_scalar($value)) {
                $out .= ' ' . (string) $value;
            }
        }

        return $out;
    }

    private function parserCanRead(string $path): bool
    {
        if (! class_exists(PdfParser::class)) {
            return false;
        }
        try {
            $parser = new PdfParser();
            $document = $parser->parseFile($path);

            return $document->getText() !== '' || count($document->getPages()) > 0;
        } catch (\Throwable) {
            return false;
        }
    }

    /** Hard cap on the number of streams processed per file (DoS bound). */
    private const MAX_STREAMS = 4096;

    /**
     * Inflate all stream objects and return the concatenated decoded bytes.
     *
     * Bounds (fail-closed against decompression DoS): the running output is
     * checked BEFORE each stream is inflated and inflation is bounded to the
     * remaining scan budget, so a single bomb cannot expand past the cap.
     */
    protected function decodeStreams(string $content): string
    {
        $out = '';
        // The "stream" keyword may be followed by CRLF, LF, or a bare CR (lenient
        // PDF readers accept all three); requiring \n let a CR-only objstm hide a
        // compressed /JavaScript object from the scan surface.
        $count = preg_match_all('/stream(?:\r\n|\n|\r)(.*?)(?:\r\n|\n|\r)?endstream/s', $content, $matches, PREG_OFFSET_CAPTURE);
        if ($count === 0 || $count === false) {
            return '';
        }

        $budget = $this->maxScanSize();
        $processed = 0;

        foreach ($matches[1] as [$raw, $offset]) {
            if (++$processed > self::MAX_STREAMS) {
                break; // bounded number of streams
            }
            // Stop before inflating once the budget is already spent.
            $remaining = $budget - strlen($out);
            if ($remaining <= 0) {
                break;
            }

            // Locate the dictionary by walking back to the "<<" that opens this
            // stream object's dict, rather than a fixed-size window an attacker
            // can simply pad past.
            $dict = $this->streamDictionary($content, $offset);

            $decodedChunk = $this->applyFilters($raw, $dict, $content, $remaining);
            if ($decodedChunk !== '') {
                $out .= "\n" . $decodedChunk;
            }
            if (strlen($out) > $budget) {
                break; // bounded work
            }
        }

        return $out;
    }

    /**
     * Walk backward from a stream's data offset to the matching "<<" that opens
     * this object's dictionary, returning the full dict text. Falls back to a
     * generous window if the matching open cannot be located.
     */
    private function streamDictionary(string $content, int $streamOffset): string
    {
        // The "stream" keyword sits just before $streamOffset; find the ">>"
        // that closes the dict (searching backward from the stream data).
        $head = substr($content, 0, $streamOffset);
        $dictEnd = strrpos($head, '>>');
        if ($dictEnd === false) {
            return substr($content, max(0, $streamOffset - 4096), $streamOffset - max(0, $streamOffset - 4096));
        }

        // Balance "<<" / ">>" walking backward to find this dict's opening "<<".
        $depth = 0;
        $i = $dictEnd;
        $openPos = null;
        while ($i >= 1) {
            $pair = substr($content, $i - 1, 2);
            if ($pair === '>>') {
                $depth++;
                $i -= 2;

                continue;
            }
            if ($pair === '<<') {
                $depth--;
                if ($depth === 0) {
                    $openPos = $i - 1;
                    break;
                }
                $i -= 2;

                continue;
            }
            $i--;
        }

        if ($openPos === null) {
            return substr($content, max(0, $streamOffset - 4096), $streamOffset - max(0, $streamOffset - 4096));
        }

        return substr($content, $openPos, ($dictEnd + 2) - $openPos);
    }

    private function applyFilters(string $raw, string $dict, string $content, int $maxLength): string
    {
        $data = $raw;

        // Resolve an indirect /Filter reference ("/Filter 12 0 R") to the value
        // of the referenced object so its decoder name is honoured.
        $filterText = $this->resolveIndirectValue($dict, 'Filter', $content) ?? $dict;

        if (preg_match('/\/ASCIIHexDecode\b/', $filterText)) {
            $data = $this->asciiHexDecode($data) ?? $data;
        }
        if (preg_match('/\/ASCII85Decode\b/', $filterText)) {
            $data = $this->ascii85Decode($data) ?? $data;
        }
        if (preg_match('/\/(FlateDecode|Fl)\b/', $filterText)) {
            $data = $this->flateDecode($data, $maxLength) ?? $data;
        }
        if (preg_match('/\/LZWDecode\b/', $filterText)) {
            $data = $this->lzwDecode($data) ?? $data;
        }

        // Fail-closed insurance against a decoy / unresolved-indirect / oversized
        // /Filter that hid the real one: FlateDecode is by far the most common
        // stream filter, so when it was NOT among the declared filters, also try
        // to inflate the raw bytes. On non-deflate input this fails cleanly and
        // adds nothing; on the decoy attack it reveals the compressed payload the
        // declared (decoy) filter tried to keep opaque.
        if (! preg_match('/\/(FlateDecode|Fl)\b/', $filterText)) {
            $opportunistic = $this->flateDecode($raw, $maxLength);
            if ($opportunistic !== null && $opportunistic !== '' && $opportunistic !== $data) {
                $data .= "\n" . $opportunistic;
            }
        }

        // Even with no recognized filter, return the raw bytes (they may be plain).
        return $data;
    }

    /**
     * If the dict gives "/<Key> N G R" (an indirect reference), return the body
     * of object "N G obj ... endobj"; otherwise null.
     */
    private function resolveIndirectValue(string $dict, string $key, string $content): ?string
    {
        if (! preg_match('/\/' . preg_quote($key, '/') . '\s+(\d+)\s+(\d+)\s+R\b/', $dict, $m)) {
            return null;
        }
        $num = $m[1];
        $gen = $m[2];
        // Resolve to the object body. If the same object number is defined more
        // than once (a decoy planted before the real object to mis-route the
        // decoder), treat the reference as ambiguous and return null — we never
        // trust an attacker-chosen filter name. The opportunistic FlateDecode in
        // applyFilters() still inflates the raw bytes in that case (fail-closed).
        // (?<!\d) prevents "15 0 obj" from matching a "5 0 obj" reference.
        $n = preg_match_all('/(?<!\d)' . $num . '\s+' . $gen . '\s+obj\b(.*?)\bendobj\b/s', $content, $objs);
        if ($n !== 1) {
            return null;
        }

        return $objs[1][0];
    }

    private function flateDecode(string $data, int $maxLength = 0): ?string
    {
        // Bound inflation to the remaining scan budget so a tiny stream cannot
        // expand into an out-of-memory bomb. A non-positive bound means "no
        // additional budget" — treat as a small floor so we still surface a
        // little content for inspection without risking a blow-up.
        $limit = $maxLength > 0 ? $maxLength : 1;

        $trimmed = ltrim($data, "\r\n");
        $result = @gzuncompress($trimmed, $limit);
        if ($result === false) {
            $result = @gzinflate($trimmed, $limit);
        }
        if ($result === false) {
            $result = @gzinflate(substr($trimmed, 2), $limit); // skip zlib header
        }

        return $result === false ? null : $result;
    }

    private function asciiHexDecode(string $data): ?string
    {
        $hex = preg_replace('/[^0-9a-fA-F]/', '', strtok($data, '>'));
        if ($hex === null || $hex === '') {
            return null;
        }
        if (strlen($hex) % 2 === 1) {
            $hex .= '0';
        }
        $bin = @hex2bin($hex);

        return $bin === false ? null : $bin;
    }

    private function ascii85Decode(string $data): ?string
    {
        $data = preg_replace('/\s+/', '', $data) ?? $data;
        $data = preg_replace('/^<~/', '', $data) ?? $data;
        $end = strpos($data, '~>');
        if ($end !== false) {
            $data = substr($data, 0, $end);
        }
        if ($data === '') {
            return null;
        }

        $out = '';
        $chunk = [];
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $ch = $data[$i];
            if ($ch === 'z' && $chunk === []) {
                $out .= "\0\0\0\0";

                continue;
            }
            $val = ord($ch) - 33;
            if ($val < 0 || $val > 84) {
                continue;
            }
            $chunk[] = $val;
            if (count($chunk) === 5) {
                $num = 0;
                foreach ($chunk as $c) {
                    $num = $num * 85 + $c;
                }
                $out .= chr(($num >> 24) & 0xFF) . chr(($num >> 16) & 0xFF) . chr(($num >> 8) & 0xFF) . chr($num & 0xFF);
                $chunk = [];
            }
        }
        if (count($chunk) > 1) {
            $n = count($chunk);
            for ($i = $n; $i < 5; $i++) {
                $chunk[] = 84;
            }
            $num = 0;
            foreach ($chunk as $c) {
                $num = $num * 85 + $c;
            }
            $bytes = chr(($num >> 24) & 0xFF) . chr(($num >> 16) & 0xFF) . chr(($num >> 8) & 0xFF) . chr($num & 0xFF);
            $out .= substr($bytes, 0, $n - 1);
        }

        return $out;
    }

    private function lzwDecode(string $data): ?string
    {
        // Minimal PDF LZW (variable code width, early change) decoder.
        $bytes = array_values(unpack('C*', $data) ?: []);
        if ($bytes === []) {
            return null;
        }

        $dict = [];
        for ($i = 0; $i < 256; $i++) {
            $dict[$i] = chr($i);
        }
        $dictSize = 258; // 256 + clear(256) + eod(257)
        $codeWidth = 9;
        $bitBuffer = 0;
        $bitCount = 0;
        $prev = null;
        $out = '';

        foreach ($bytes as $byte) {
            $bitBuffer = ($bitBuffer << 8) | $byte;
            $bitCount += 8;
            while ($bitCount >= $codeWidth) {
                $bitCount -= $codeWidth;
                $code = ($bitBuffer >> $bitCount) & ((1 << $codeWidth) - 1);

                if ($code === 256) { // clear table
                    $dict = [];
                    for ($i = 0; $i < 256; $i++) {
                        $dict[$i] = chr($i);
                    }
                    $dictSize = 258;
                    $codeWidth = 9;
                    $prev = null;

                    continue;
                }
                if ($code === 257) { // end of data
                    return $out;
                }

                if (isset($dict[$code])) {
                    $entry = $dict[$code];
                } elseif ($prev !== null) {
                    $entry = $prev . $prev[0];
                } else {
                    return $out === '' ? null : $out;
                }

                $out .= $entry;
                if ($prev !== null) {
                    $dict[$dictSize++] = $prev . $entry[0];
                }
                $prev = $entry;

                if ($dictSize + 1 >= (1 << $codeWidth) && $codeWidth < 12) {
                    $codeWidth++;
                }
                if (strlen($out) > $this->maxScanSize()) {
                    return $out;
                }
            }
        }

        return $out;
    }

    /**
     * Decode PDF name #xx hex escapes so /J#61vaScript becomes /JavaScript.
     */
    private function decodeHexNames(string $content): string
    {
        return preg_replace_callback('/#([0-9A-Fa-f]{2})/', static function ($m) {
            return chr(hexdec($m[1]));
        }, $content) ?? $content;
    }

    private function matchesName(string $surface, string $name): bool
    {
        // Anchor: name is a PDF token; the next char must be a delimiter/whitespace.
        $quoted = preg_quote($name, '/');

        return (bool) preg_match('/' . $quoted . '(?=[\s\/<>\[\](){}]|$)/', $surface);
    }

    /**
     * @return array<string>
     */
    private function activeNames(): array
    {
        $custom = (array) $this->getConfig('safeguard.pdf_scanning.custom_dangerous_actions', []);
        $exclude = (array) $this->getConfig('safeguard.pdf_scanning.exclude_actions', []);
        $names = array_merge($this->dangerousNames, array_filter($custom, 'is_string'));

        return array_values(array_diff(array_unique($names), $exclude));
    }

    public function isPdf(UploadedFile|string $file): bool
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        if ($path === false || ! is_file($path)) {
            return false;
        }
        $head = @file_get_contents($path, false, null, 0, 8);

        return $head !== false && str_starts_with($head, '%PDF-');
    }

    /**
     * @return array{safe: bool, threats: array<string>, has_javascript: bool, has_external_links: bool}
     */
    private function result(bool $safe, array $threats): array
    {
        return [
            'safe' => $safe,
            'threats' => array_values(array_unique($threats)),
            'has_javascript' => false,
            'has_external_links' => false,
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
