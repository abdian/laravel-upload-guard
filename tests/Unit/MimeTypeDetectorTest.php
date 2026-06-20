<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\MimeTypeDetector;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;

class MimeTypeDetectorTest extends TestCase
{
    private MimeTypeDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        MimeTypeDetector::flushCache();
        $this->detector = new MimeTypeDetector();
    }

    private function detect(string $bytes, string $name = 'sample.bin'): ?string
    {
        $path = $this->scratchPath($name);
        Fixtures::writeTo($path, $bytes);
        MimeTypeDetector::flushCache();

        return $this->detector->detect($path);
    }

    public function test_detects_common_images(): void
    {
        $this->assertSame('image/png', $this->detect(Fixtures::png(), 'a.png'));
        $this->assertSame('image/jpeg', $this->detect(Fixtures::jpeg(), 'a.jpg'));
        $this->assertSame('image/gif', $this->detect(Fixtures::gif(), 'a.gif'));
        $this->assertSame('image/bmp', $this->detect(Fixtures::bmp(), 'a.bmp'));
    }

    public function test_pdf_detected(): void
    {
        $this->assertSame('application/pdf', $this->detect(Fixtures::pdf(), 'a.pdf'));
    }

    public function test_bm_prefixed_garbage_is_not_a_bmp(): void
    {
        $this->assertNotSame('image/bmp', $this->detect(Fixtures::fakeBmpPrefix(), 'fake.bmp'));
    }

    public function test_legacy_xls_disambiguated_as_excel_not_word(): void
    {
        // The historical false positive: real .xls detected as application/msword.
        $this->assertSame('application/vnd.ms-excel', $this->detect(Fixtures::legacyXls(), 'book.xls'));
    }

    public function test_legacy_doc_detected_as_word(): void
    {
        $this->assertSame('application/msword', $this->detect(Fixtures::legacyOleBenign(), 'doc.doc'));
    }

    public function test_docx_disambiguated(): void
    {
        $this->assertSame(
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            $this->detect(Fixtures::docx(), 'a.docx')
        );
    }

    public function test_jar_detected_and_dangerous(): void
    {
        $mime = $this->detect(Fixtures::jar(), 'a.jar');
        $this->assertSame('application/java-archive', $mime);
        $this->assertTrue($this->detector->isDangerous($mime));
    }

    public function test_appended_polyglot_classified_by_real_container(): void
    {
        $this->assertSame('image/jpeg', $this->detect(Fixtures::phpInJpeg(), 'p.jpg'));
        $this->assertSame('image/png', $this->detect(Fixtures::phpInPng(), 'p.png'));
        $this->assertSame('application/pdf', $this->detect(Fixtures::phpInPdf(), 'p.pdf'));
    }

    public function test_unknown_binary_is_null_not_octet_stream(): void
    {
        $this->assertNull($this->detect(Fixtures::phpInOctetStream(), 'x.bin'));
    }

    public function test_text_sources_classified_as_text(): void
    {
        $this->assertSame('text/plain', $this->detect(Fixtures::javascriptSource(), 'a.js'));
        $this->assertSame('text/plain', $this->detect(Fixtures::csv(), 'a.csv'));
    }

    public function test_svg_detected(): void
    {
        $this->assertSame('image/svg+xml', $this->detect(Fixtures::benignSvg(), 'a.svg'));
    }

    public function test_detection_is_memoized_and_consistent(): void
    {
        $path = $this->scratchPath('memo.png');
        Fixtures::writeTo($path, Fixtures::png());
        MimeTypeDetector::flushCache();

        $first = $this->detector->detect($path);
        $second = $this->detector->detect($path);
        $this->assertSame($first, $second);
        $this->assertSame('image/png', $first);
    }

    public function test_static_cache_is_bounded_and_evicts_oldest(): void
    {
        // Each distinct temp path produces a distinct cache key (realpath|mtime|
        // size). Under Octane/queue workers these are unique per request, so the
        // memo must NOT grow without bound. Detect many distinct files and assert
        // the static cache is capped (FIFO eviction), not that it equals N.
        MimeTypeDetector::flushCache();

        $total = 700; // comfortably above the 512 cap
        for ($i = 0; $i < $total; $i++) {
            $path = $this->scratchPath("cap-{$i}.png");
            Fixtures::writeTo($path, Fixtures::png());
            // Do NOT flush between detections — we are exercising accumulation.
            $this->assertSame('image/png', $this->detector->detect($path));
        }

        $this->assertLessThanOrEqual(512, MimeTypeDetector::cacheSize());
        $this->assertGreaterThan(0, MimeTypeDetector::cacheSize());
    }

    public function test_detection_still_correct_after_eviction(): void
    {
        // Correctness of known fixtures must be unchanged even after the cache
        // has churned past its cap.
        MimeTypeDetector::flushCache();
        for ($i = 0; $i < 600; $i++) {
            $path = $this->scratchPath("churn-{$i}.png");
            Fixtures::writeTo($path, Fixtures::png());
            $this->detector->detect($path);
        }

        $this->assertLessThanOrEqual(512, MimeTypeDetector::cacheSize());

        $png = $this->scratchPath('after.png');
        Fixtures::writeTo($png, Fixtures::png());
        $this->assertSame('image/png', $this->detector->detect($png));

        $pdf = $this->scratchPath('after.pdf');
        Fixtures::writeTo($pdf, Fixtures::pdf());
        $this->assertSame('application/pdf', $this->detector->detect($pdf));
    }
}
