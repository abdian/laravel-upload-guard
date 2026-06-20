<?php

namespace Abdian\UploadGuard\Tests\Regression;

use Abdian\UploadGuard\Rules\Safeguard;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * One regression test per confirmed historical bypass. Each asserts the
 * hardened, end-to-end `safeguard` rule now rejects (or sanitizes) the input.
 */
class ConfirmedBypassesTest extends TestCase
{
    private function rejects(string $bytes, string $name): bool
    {
        $rule = new Safeguard();
        $failed = false;
        $rule->validate('file', $this->uploadedFile($bytes, $name), function () use (&$failed) {
            $failed = true;
        });

        return $failed;
    }

    #[DataProvider('polyglotProvider')]
    public function test_polyglot_rce_blocked(string $method, string $name): void
    {
        $this->assertTrue($this->rejects(Fixtures::$method(), $name), "{$method} should be blocked");
    }

    public static function polyglotProvider(): array
    {
        return [
            'jpeg' => ['phpInJpeg', 'a.jpg'],
            'png' => ['phpInPng', 'a.png'],
            'gif' => ['phpInGif', 'a.gif'],
            'bmp' => ['phpInBmp', 'a.bmp'],
            'pdf' => ['phpInPdf', 'a.pdf'],
            'zip' => ['phpInZip', 'a.zip'],
            'octet-stream' => ['phpInOctetStream', 'a.bin'],
            'pdf-php-polyglot' => ['pdfPhpPolyglot', 'a.pdf'],
        ];
    }

    public function test_compressed_pdf_javascript_blocked(): void
    {
        $this->assertTrue($this->rejects(Fixtures::pdfFlateJs(), 'a.pdf'));
    }

    public function test_hex_escaped_pdf_javascript_blocked(): void
    {
        $this->assertTrue($this->rejects(Fixtures::pdfHexEscapedJsName(), 'a.pdf'));
    }

    public function test_pdf_openaction_javascript_blocked(): void
    {
        $this->assertTrue($this->rejects(Fixtures::pdfOpenActionJs(), 'a.pdf'));
    }

    public function test_unquoted_handler_svg_neutralized_or_blocked(): void
    {
        $file = $this->uploadedFile(Fixtures::svgUnquotedHandler(), 'a.svg');
        $rule = new Safeguard();
        $failed = false;
        $rule->validate('file', $file, function () use (&$failed) {
            $failed = true;
        });
        $cleaned = (string) @file_get_contents($file->getRealPath());
        $this->assertTrue($failed || ! preg_match('/onload|onclick/i', $cleaned));
    }

    public function test_external_dtd_xxe_svg_blocked_or_stripped(): void
    {
        $file = $this->uploadedFile(Fixtures::svgExternalDtdSystem(), 'a.svg');
        $rule = new Safeguard();
        $failed = false;
        $rule->validate('file', $file, function () use (&$failed) {
            $failed = true;
        });
        $cleaned = (string) @file_get_contents($file->getRealPath());
        $this->assertTrue($failed || ! preg_match('/<!DOCTYPE|etc\/passwd/i', $cleaned));
    }

    public function test_forged_size_zip_bomb_blocked(): void
    {
        config(['safeguard.archive_scanning.max_decompressed_size' => 1024 * 1024]);
        $this->assertTrue($this->rejects(Fixtures::zipForgedSize(5), 'a.zip'));
    }

    public function test_classic_zip_bomb_blocked(): void
    {
        config(['safeguard.archive_scanning.max_decompressed_size' => 1024 * 1024]);
        $this->assertTrue($this->rejects(Fixtures::zipBomb(5), 'a.zip'));
    }

    public function test_legacy_ole_macro_blocked(): void
    {
        $this->assertTrue($this->rejects(Fixtures::legacyOleMacroDoc(), 'a.doc'));
    }

    public function test_case_variant_ooxml_macro_blocked(): void
    {
        $this->assertTrue($this->rejects(Fixtures::docxLowercaseContentTypes(), 'a.docx'));
    }

    public function test_decompression_bomb_image_blocked(): void
    {
        $this->assertTrue($this->rejects(Fixtures::decompressionBombPng(), 'a.png'));
    }

    public function test_archive_path_traversal_blocked(): void
    {
        $this->assertTrue($this->rejects(Fixtures::zipTraversalBenign(), 'a.zip'));
    }

    public function test_archive_symlink_entry_blocked(): void
    {
        $this->assertTrue($this->rejects(Fixtures::zipSymlink(), 'a.zip'));
    }

    public function test_nested_archive_scanned(): void
    {
        $this->assertTrue($this->rejects(Fixtures::zipNested(), 'a.zip'));
    }
}
