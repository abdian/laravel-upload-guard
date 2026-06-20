<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\Quarantine;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;

class QuarantineTest extends TestCase
{
    private function quarantineDir(): string
    {
        $dir = $this->scratchPath('quarantine-' . bin2hex(random_bytes(3)));

        return $dir;
    }

    public function test_disabled_by_default_does_not_copy(): void
    {
        $dir = $this->quarantineDir();
        config(['safeguard.quarantine.enabled' => false, 'safeguard.quarantine.path' => $dir]);

        $src = $this->scratchPath('q1.bin');
        Fixtures::writeTo($src, Fixtures::phpInJpeg());

        $this->assertFalse(Quarantine::store($src, ['threats' => ['x']]));
        $this->assertFalse(is_dir($dir) && count(glob($dir . '/*')) > 0);
    }

    public function test_enabled_stores_file_and_sanitized_metadata(): void
    {
        $dir = $this->quarantineDir();
        config(['safeguard.quarantine.enabled' => true, 'safeguard.quarantine.path' => $dir]);

        $src = $this->scratchPath('q2.bin');
        Fixtures::writeTo($src, Fixtures::phpInJpeg());

        $ok = Quarantine::store($src, [
            'detected_type' => 'image/jpeg',
            'threats' => ["bad\r\nthreat"],
        ]);
        $this->assertTrue($ok);

        $blobs = glob($dir . '/*.bin');
        $metas = glob($dir . '/*.json');
        $this->assertCount(1, $blobs);
        $this->assertCount(1, $metas);

        $meta = json_decode((string) file_get_contents($metas[0]), true);
        $this->assertSame('image/jpeg', $meta['detected_type']);
        // Control characters stripped from threat strings.
        $this->assertStringNotContainsString("\r", $meta['threats'][0]);
        $this->assertStringNotContainsString("\n", $meta['threats'][0]);
    }

    public function test_stored_blob_and_metadata_are_owner_only_0600(): void
    {
        $dir = $this->quarantineDir();
        config(['safeguard.quarantine.enabled' => true, 'safeguard.quarantine.path' => $dir]);

        // Loosen the process umask so an unchmod'd write would land at 0644 (group/world readable).
        $oldUmask = umask(0);

        try {
            $src = $this->scratchPath('q4.bin');
            Fixtures::writeTo($src, Fixtures::phpInJpeg());

            $this->assertTrue(Quarantine::store($src, ['threats' => ['x']]));

            $blobs = glob($dir . '/*.bin');
            $metas = glob($dir . '/*.json');
            $this->assertCount(1, $blobs);
            $this->assertCount(1, $metas);

            if (DIRECTORY_SEPARATOR === '\\') {
                $this->markTestSkipped('chmod is a no-op on Windows.');
            }

            clearstatcache();
            // Quarantined malware blob must be owner-only — never group/world readable.
            $this->assertSame(0600, fileperms($blobs[0]) & 0777);
            // Metadata sidecar must be locked down too.
            $this->assertSame(0600, fileperms($metas[0]) & 0777);
        } finally {
            umask($oldUmask);
        }
    }

    public function test_unwritable_path_does_not_throw_or_fail_open(): void
    {
        // Point at a path under a file (cannot be a directory) -> mkdir fails.
        $blocker = $this->scratchPath('blocker.txt');
        file_put_contents($blocker, 'x');
        config(['safeguard.quarantine.enabled' => true, 'safeguard.quarantine.path' => $blocker . '/sub']);

        $src = $this->scratchPath('q3.bin');
        Fixtures::writeTo($src, 'data');

        // Must return false (no crash) — quarantine failure never fails open.
        $this->assertFalse(Quarantine::store($src, ['threats' => ['x']]));
    }
}
