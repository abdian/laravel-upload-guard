<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\ImageScanner;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;

class ImageScannerTest extends TestCase
{
    private ImageScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new ImageScanner();
    }

    private function write(string $bytes, string $name): string
    {
        $path = $this->scratchPath($name);

        return Fixtures::writeTo($path, $bytes);
    }

    public function test_benign_images_pass(): void
    {
        $this->assertTrue($this->scanner->scan($this->write(Fixtures::png(), 'a.png'))['safe']);
        $this->assertTrue($this->scanner->scan($this->write(Fixtures::jpeg(), 'a.jpg'))['safe']);
        $this->assertTrue($this->scanner->scan($this->write(Fixtures::gif(), 'a.gif'))['safe']);
    }

    public function test_decompression_bomb_png_rejected_before_decode(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::decompressionBombPng(), 'bomb.png'));
        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(array_filter($result['threats'], fn ($t) => str_contains($t, 'pixel cap')));
    }

    public function test_code_in_comment_segment_detected(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::jpegWithCommentCode(), 'meta.jpg'));
        $this->assertFalse($result['safe']);
    }

    public function test_appended_payload_detected_as_trailing(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::phpInPng(), 'p.png'));
        $this->assertTrue($result['trailing_data']);
        $this->assertFalse($result['safe']);
    }

    public function test_single_extra_gif_trailer_detected(): void
    {
        $result = $this->scanner->scan($this->write(Fixtures::gifExtraTrailer(), 't.gif'));
        $this->assertTrue($result['trailing_data']);
    }

    public function test_reencode_strips_payload(): void
    {
        $path = $this->write(Fixtures::phpInJpeg(), 're.jpg');
        $this->assertTrue($this->scanner->reencode($path));

        $stored = file_get_contents($path);
        $this->assertStringNotContainsString('<?php', $stored);
        $this->assertTrue($this->scanner->scan($path)['safe']);
    }

    public function test_reencode_rejects_decompression_bomb_without_prior_scan(): void
    {
        // Tiny PNG declaring 50000x50000 pixels. reencode() must apply its own
        // bomb guard BEFORE any decode, regardless of whether scan() ran first.
        $path = $this->write(Fixtures::decompressionBombPng(), 'reencode-bomb.png');

        $this->assertFalse($this->scanner->reencode($path));
    }

    // ---------------------------------------------------------------------
    // Regression: TIFF / BigTIFF decompression bombs.
    // ---------------------------------------------------------------------

    /** Build a classic little-endian TIFF declaring width x height (LONG fields). */
    private function classicTiff(int $w, int $h): string
    {
        $entry = function (int $tag, int $type, int $count, int $value): string {
            return pack('v', $tag) . pack('v', $type) . pack('V', $count) . pack('V', $value);
        };
        $ifd = pack('v', 7) // entry count
            . $entry(0x0100, 4, 1, $w)   // ImageWidth  (LONG)
            . $entry(0x0101, 4, 1, $h)   // ImageLength (LONG)
            . $entry(0x0102, 3, 1, 8)    // BitsPerSample
            . $entry(0x0103, 3, 1, 1)    // Compression
            . $entry(0x0106, 3, 1, 1)    // Photometric
            . $entry(0x0111, 4, 1, 8)    // StripOffsets
            . $entry(0x0116, 4, 1, $h)   // RowsPerStrip
            . pack('V', 0);              // next IFD offset

        // Header: "II", 0x2A, 0x00, IFD offset = 8.
        return "II\x2A\x00" . pack('V', 8) . $ifd;
    }

    /** Build a little-endian BigTIFF declaring width x height (LONG8 fields). */
    private function bigTiff(int $w, int $h): string
    {
        // 20-byte entries: tag(2) type(2) count(8) value(8). LONG8 = type 16.
        $entry = function (int $tag, int $type, int $count, int $value): string {
            return pack('v', $tag) . pack('v', $type)
                . pack('P', $count) . pack('P', $value);
        };
        $ifd = pack('P', 4) // 8-byte entry count
            . $entry(0x0100, 16, 1, $w)   // ImageWidth  (LONG8)
            . $entry(0x0101, 16, 1, $h)   // ImageLength (LONG8)
            . $entry(0x0102, 3, 1, 8)     // BitsPerSample
            . $entry(0x0103, 3, 1, 1)     // Compression
            . pack('P', 0);               // next IFD offset

        // Header: "II", 0x2B, 0x00, bytesize-of-offsets(8), 0x0000, IFD offset(8)=16.
        return "II\x2B\x00" . pack('v', 8) . pack('v', 0) . pack('P', 16) . $ifd;
    }

    public function test_classic_tiff_decompression_bomb_rejected(): void
    {
        $result = $this->scanner->scan($this->write($this->classicTiff(200000, 200000), 'bomb.tiff'));
        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(array_filter(
            $result['threats'],
            fn ($t) => str_contains($t, 'pixel cap') || str_contains($t, 'could not be determined')
        ));
    }

    public function test_bigtiff_decompression_bomb_rejected(): void
    {
        $result = $this->scanner->scan($this->write($this->bigTiff(200000, 200000), 'bomb.bigtiff.tif'));
        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(array_filter(
            $result['threats'],
            fn ($t) => str_contains($t, 'pixel cap') || str_contains($t, 'could not be determined')
        ));
    }

    public function test_image_signature_without_dimensions_fails_closed(): void
    {
        // BigTIFF header with a garbage/unreachable IFD offset: no parser can read
        // dimensions, so the guard must fail closed rather than skip the cap.
        $bytes = "II\x2B\x00" . pack('v', 8) . pack('v', 0) . pack('P', 0xFFFFFFFF);
        $result = $this->scanner->scan($this->write($bytes, 'nodim.tif'));
        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(array_filter(
            $result['threats'],
            fn ($t) => str_contains($t, 'could not be determined')
        ));
    }

    // ---------------------------------------------------------------------
    // Regression: BMP/TIFF content-sniffing polyglots.
    // ---------------------------------------------------------------------

    public function test_bmp_with_appended_script_rejected(): void
    {
        $bmp = Fixtures::bmp(); // valid small BMP
        $payload = $bmp . "\n<!DOCTYPE html><html><body><script>alert(document.domain)</script></body></html>";
        $result = $this->scanner->scan($this->write($payload, 'poly.bmp'));

        $this->assertFalse($result['safe']);
        // Caught both structurally (trailing past declared BMP size) and by content sniff.
        $this->assertTrue($result['trailing_data']);
        $this->assertNotEmpty(array_filter(
            $result['threats'],
            fn ($t) => str_contains($t, 'content-sniffing') || str_contains($t, 'Trailing')
        ));
    }

    public function test_gif_with_embedded_script_rejected(): void
    {
        // GIF carrying HTML/script inside the container (content-sniffing XSS).
        $gif = "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
            . "\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
            . "/*;*/<html><script>alert(document.domain)</script></html>";
        $result = $this->scanner->scan($this->write($gif, 'poly.gif'));

        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(array_filter(
            $result['threats'],
            fn ($t) => str_contains($t, 'content-sniffing') || str_contains($t, 'Trailing')
        ));
    }

    public function test_benign_images_still_pass_after_hardening(): void
    {
        $this->assertTrue($this->scanner->scan($this->write(Fixtures::png(), 'ok.png'))['safe']);
        $this->assertTrue($this->scanner->scan($this->write(Fixtures::jpeg(), 'ok.jpg'))['safe']);
        $this->assertTrue($this->scanner->scan($this->write(Fixtures::gif(), 'ok.gif'))['safe']);
        $this->assertTrue($this->scanner->scan($this->write(Fixtures::bmp(), 'ok.bmp'))['safe']);

        // A small, well-formed classic TIFF (under the pixel cap) must pass.
        $this->assertTrue($this->scanner->scan($this->write($this->classicTiff(2, 2), 'ok.tiff'))['safe']);
    }
}
