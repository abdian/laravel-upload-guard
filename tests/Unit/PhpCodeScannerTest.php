<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\PhpCodeScanner;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class PhpCodeScannerTest extends TestCase
{
    private PhpCodeScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new PhpCodeScanner();
    }

    private function scan(string $bytes, string $name = 'sample.bin'): array
    {
        $path = $this->scratchPath($name);
        Fixtures::writeTo($path, $bytes);

        return $this->scanner->scan($path);
    }

    #[DataProvider('polyglotProvider')]
    public function test_php_opener_detected_in_every_binary_type(string $method, string $name): void
    {
        $result = $this->scan(Fixtures::$method(), $name);
        $this->assertFalse($result['safe'], "Expected {$method} to be flagged");
    }

    public static function polyglotProvider(): array
    {
        return [
            'jpeg' => ['phpInJpeg', 'p.jpg'],
            'png' => ['phpInPng', 'p.png'],
            'gif' => ['phpInGif', 'p.gif'],
            'bmp' => ['phpInBmp', 'p.bmp'],
            'pdf' => ['phpInPdf', 'p.pdf'],
            'octet-stream' => ['phpInOctetStream', 'p.bin'],
            'pdf-php-polyglot' => ['pdfPhpPolyglot', 'p.pdf'],
        ];
    }

    public function test_benign_images_pass(): void
    {
        $this->assertTrue($this->scan(Fixtures::png(), 'a.png')['safe']);
        $this->assertTrue($this->scan(Fixtures::jpeg(), 'a.jpg')['safe']);
        $this->assertTrue($this->scan(Fixtures::gif(), 'a.gif')['safe']);
        $this->assertTrue($this->scan(Fixtures::bmp(), 'a.bmp')['safe']);
    }

    public function test_benign_source_files_do_not_false_positive(): void
    {
        // These mention eval/system/exec/require OUTSIDE any PHP open tag.
        $this->assertTrue($this->scan(Fixtures::javascriptSource(), 'a.js')['safe']);
        $this->assertTrue($this->scan(Fixtures::pythonSource(), 'a.py')['safe']);
        $this->assertTrue($this->scan(Fixtures::csv(), 'a.csv')['safe']);
        $this->assertTrue($this->scan(Fixtures::markdown(), 'a.md')['safe']);
    }

    public function test_short_echo_tag_flagged(): void
    {
        $this->assertFalse($this->scan(Fixtures::phpShortTag(), 'a.txt')['safe']);
    }

    public function test_dangerous_function_inside_php_region_flagged(): void
    {
        $result = $this->scan(Fixtures::phpDangerousFunction(), 'a.php');
        $this->assertFalse($result['safe']);
    }

    public function test_variable_function_dispatch_flagged_via_tokens(): void
    {
        $result = $this->scan(Fixtures::phpVariableFunction(), 'a.php');
        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(array_filter($result['threats'], fn ($t) => str_contains($t, 'Dynamic dispatch')));
    }

    public function test_xmp_packet_does_not_false_positive(): void
    {
        // XMP metadata uses xpacket processing instructions which must NOT be flagged as a bare short tag.
        $xmp = "\xFF\xD8\xFF\xE1<?xpacket begin=\"\xEF\xBB\xBF\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>"
            . "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"></x:xmpmeta><?xpacket end=\"w\"?>";
        $result = $this->scan($xmp, 'meta.bin');
        $this->assertTrue($result['safe'], 'XMP packet should not be flagged: ' . implode(',', $result['threats']));
    }

    public function test_bare_short_tag_without_whitespace_is_flagged(): void
    {
        // Regression: with short_open_tag enabled, "<?" directly followed by a
        // token (no whitespace) is valid executable PHP and must be detected.
        $this->assertFalse($this->scan('<?system($_GET[0]);', 'a.txt')['safe'], '"<?system(...)" must be flagged');
        $this->assertFalse($this->scan('<?$x=system($_GET[0]);', 'b.txt')['safe'], '"<?$x=..." must be flagged');
    }

    #[DataProvider('bareShortTagBypassProvider')]
    public function test_bare_short_tag_with_arbitrary_follow_char_is_flagged(string $bytes, string $name): void
    {
        // Red-team bypasses: "<?" followed by '{', ';' (or any char outside the
        // former narrow class) is still valid executable PHP and must be flagged.
        $result = $this->scan($bytes, $name);
        $this->assertFalse($result['safe'], "Expected {$name} to be flagged: " . $bytes);
    }

    public static function bareShortTagBypassProvider(): array
    {
        return [
            'brace-shell'  => ['<?{}system($_GET[0]);', 'a.txt'],
            'semi-shell'   => ['<?;system($_GET[0]);', 'b.txt'],
            'brace-close'  => ['<?}system($_GET[0]);', 'c.txt'],
            'brace-info'   => ['<?{}phpinfo();', 'd.txt'],
            'tab-follow'   => ["<?\t" . 'system($_GET[0]);', 'e.txt'],
            'newline-only' => ["<?\n" . 'system($_GET[0]);', 'f.txt'],
        ];
    }

    #[DataProvider('aspJspBypassProvider')]
    public function test_asp_jsp_letter_after_tag_is_flagged(string $bytes, string $name): void
    {
        // Red-team bypasses: a letter / "!" right after "<%" (e.g. <%eval,
        // <%Runtime, <%!) previously slipped past the narrow /<%[=@\s]/ rule.
        $result = $this->scan($bytes, $name);
        $this->assertFalse($result['safe'], "Expected {$name} to be flagged: " . $bytes);
    }

    public static function aspJspBypassProvider(): array
    {
        return [
            'asp-eval'      => ['<%eval request("c")%>', 'a.asp'],
            'jsp-runtime'   => ['<%Runtime.getRuntime().exec("id");%>', 'b.jsp'],
            'asp-out'       => ['<%out.println("x");%>', 'c.jsp'],
            'asp-decl-bang' => ['<%! int x = 1; %>', 'd.jsp'],
        ];
    }

    public function test_xml_processing_instruction_does_not_false_positive(): void
    {
        // A plain XML document declaration must NOT be flagged as a PHP short tag.
        $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n" . '<root><item>hello</item></root>';
        $result = $this->scan($xml, 'doc.xml');
        $this->assertTrue($result['safe'], 'XML declaration should not be flagged: ' . implode(',', $result['threats']));
    }
}
