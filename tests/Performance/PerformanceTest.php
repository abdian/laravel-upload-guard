<?php

namespace Abdian\UploadGuard\Tests\Performance;

use Abdian\UploadGuard\ArchiveScanner;
use Abdian\UploadGuard\PhpCodeScanner;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;

/**
 * Performance budget guard. Bounds are intentionally generous to avoid CI
 * flakiness while still catching pathological regressions (unbounded passes,
 * full decompression of bombs, etc.).
 */
class PerformanceTest extends TestCase
{
    private const TIME_BUDGET_SECONDS = 5.0;
    private const MEMORY_BUDGET_BYTES = 192 * 1024 * 1024;

    public function test_large_benign_file_scan_is_bounded(): void
    {
        // ~4 MB of benign text.
        $path = $this->scratchPath('perf-large.txt');
        Fixtures::writeTo($path, str_repeat("lorem ipsum dolor sit amet 1234567890\n", 110_000));

        $start = microtime(true);
        $before = memory_get_peak_usage(true);

        $result = (new PhpCodeScanner())->scan($path);

        $elapsed = microtime(true) - $start;
        $used = memory_get_peak_usage(true) - $before;

        $this->assertTrue($result['safe']);
        $this->assertLessThan(self::TIME_BUDGET_SECONDS, $elapsed, 'PHP scan exceeded time budget');
        $this->assertLessThan(self::MEMORY_BUDGET_BYTES, max($used, 0), 'PHP scan exceeded memory budget');
    }

    public function test_zip_bomb_aborts_with_bounded_work(): void
    {
        config(['safeguard.archive_scanning.max_decompressed_size' => 1024 * 1024]);

        // A bomb that would expand to 50 MB if fully decompressed.
        $path = $this->scratchPath('perf-bomb.zip');
        Fixtures::writeTo($path, Fixtures::zipBomb(50));

        $start = microtime(true);
        $result = (new ArchiveScanner())->scan($path);
        $elapsed = microtime(true) - $start;

        $this->assertFalse($result['safe']);
        // Streaming must abort near the 1 MB cap, not after expanding 50 MB.
        $this->assertLessThan(self::TIME_BUDGET_SECONDS, $elapsed, 'Bomb scan was not bounded');
    }
}
