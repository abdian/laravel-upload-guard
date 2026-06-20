<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\PdfScanner;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;

class PdfScannerTest extends TestCase
{
    private PdfScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new PdfScanner();
    }

    private function write(string $bytes, string $name = 'doc.pdf'): string
    {
        $path = $this->scratchPath($name);

        return Fixtures::writeTo($path, $bytes);
    }

    public function test_benign_pdf_passes(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::pdf()));
        $this->assertTrue($result['safe'], implode(',', $result['threats']));
    }

    public function test_openaction_javascript_detected(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::pdfOpenActionJs()));
        $this->assertFalse($result['safe']);
        $this->assertTrue($result['has_javascript']);
    }

    public function test_hex_escaped_javascript_name_detected(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::pdfHexEscapedJsName()));
        $this->assertFalse($result['safe']);
    }

    public function test_javascript_inside_flate_stream_detected(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::pdfFlateJs()));
        $this->assertFalse($result['safe']);
        $this->assertTrue($result['has_javascript']);
    }

    public function test_incidental_substring_not_flagged(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::pdfIncidentalSubstring()));
        $this->assertTrue($result['safe'], 'javascript.info should not trip detection: ' . implode(',', $result['threats']));
    }

    public function test_page_count_correct_for_simple_pdf(): void
    {
        $this->assertSame(1, $this->scanner->pageCount($this->write(Fixtures::pdf())));
    }

    public function test_injected_page_tokens_do_not_inflate_count(): void
    {
        $count = $this->scanner->pageCount($this->write(Fixtures::pdfInjectedPageTokens()));
        $this->assertSame(1, $count, 'Injected comment tokens must not inflate the page count');
    }

    /**
     * Bypass: a stream whose dictionary declares its /Filter as an INDIRECT
     * reference ("/Filter 5 0 R") rather than a literal name. The literal-name
     * decoder regexes never see "/FlateDecode" inside the dict, so the DEFLATE
     * bytes were scanned compressed and the hidden /OpenAction -> /JavaScript
     * stayed invisible. The scanner must resolve the indirect reference, inflate
     * the stream, and flag the JavaScript.
     */
    public function test_indirect_filter_reference_flate_javascript_detected(): void
    {
        $inner = '10 0 obj << /S /JavaScript /JS (app.alert\\(1\\);) >> endobj';
        $compressed = (string) gzcompress($inner, 9);

        // Padding pushes any other object far away so no literal "/FlateDecode"
        // sits in the dictionary look-back window; the filter object lives only
        // AFTER the stream as an indirect target.
        $pad = str_repeat("%padding to separate objects from the stream dictionary\n", 12);

        $pdf = "%PDF-1.4\n"
            . "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n"
            . "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            . "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            . $pad
            . "4 0 obj\n<< /Filter 5 0 R /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n"
            . "5 0 obj\n/FlateDecode\nendobj\n"
            . "trailer\n<< /Root 1 0 R >>\n%%EOF\n";

        $result = $this->scanner->scan($this->write($pdf, 'indirect-filter.pdf'));

        $this->assertFalse($result['safe'], 'Indirect /Filter reference must not hide compressed JavaScript');
        $this->assertTrue($result['has_javascript']);
    }

    /**
     * Bypass: a stream dictionary padded beyond the old fixed 600-byte look-back
     * window so that "/FlateDecode" fell outside it and FlateDecode was never
     * applied — leaving the compressed JavaScript unscanned. The dictionary must
     * be located by matching its opening "<<" regardless of size.
     */
    public function test_oversized_dictionary_flate_javascript_detected(): void
    {
        $inner = '10 0 obj << /S /JavaScript /JS (app.alert\\(1\\);) >> endobj';
        $compressed = (string) gzcompress($inner, 9);

        // /FlateDecode is at the front of the dict; an 800-byte spacer pushes the
        // stream keyword more than 600 bytes past it.
        $spacer = ' /Spacer (' . str_repeat('A', 800) . ')';

        $pdf = "%PDF-1.4\n"
            . "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n"
            . "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            . "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            . "4 0 obj\n<< /Filter /FlateDecode" . $spacer . ' /Length ' . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n"
            . "trailer\n<< /Root 1 0 R >>\n%%EOF\n";

        $result = $this->scanner->scan($this->write($pdf, 'oversized-dict.pdf'));

        $this->assertFalse($result['safe'], 'Oversized dictionary must not push /FlateDecode out of view');
        $this->assertTrue($result['has_javascript']);
    }

    /**
     * Bypass variant (decoy object): the stream's /Filter is an INDIRECT
     * reference whose object number is ALSO defined by a benign decoy
     * ("/ASCIIHexDecode") placed BEFORE the real "/FlateDecode" object, so a
     * resolver that trusts the first textual match selects a non-inflating
     * filter and the payload is scanned opaque. EVERY dangerous token lives only
     * inside the compressed stream (no cleartext /OpenAction or /JS anywhere),
     * so detection depends entirely on still inflating the stream despite the
     * decoy. Defeated by ambiguity-fail-closed + opportunistic FlateDecode.
     */
    public function test_decoy_filter_object_cannot_hide_compressed_javascript(): void
    {
        $inner = '<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\); this.exportDataObject\\(\\);) >>';
        $compressed = (string) gzcompress($inner, 9);

        $pad = str_repeat("%padding between objects and the stream dictionary\n", 12);

        $pdf = "%PDF-1.4\n"
            . "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            . "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            . "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            . "5 0 obj\n/ASCIIHexDecode\nendobj\n" // decoy: same object number, BEFORE the stream
            . $pad
            . "4 0 obj\n<< /Filter 5 0 R /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n"
            . "5 0 obj\n/FlateDecode\nendobj\n" // the real filter object, AFTER the stream
            . "trailer\n<< /Root 1 0 R >>\n%%EOF\n";

        $result = $this->scanner->scan($this->write($pdf, 'decoy-filter.pdf'));

        $this->assertFalse($result['safe'], 'A decoy /Filter object must not hide compressed JavaScript');
        $this->assertTrue($result['has_javascript']);
    }
}
