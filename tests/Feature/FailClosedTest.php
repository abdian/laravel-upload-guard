<?php

namespace Abdian\UploadGuard\Tests\Feature;

use Abdian\UploadGuard\PhpCodeScanner;
use Abdian\UploadGuard\Rules\Safeguard;
use Abdian\UploadGuard\SvgScanner;
use Abdian\UploadGuard\Tests\TestCase;
use Illuminate\Http\UploadedFile;

/**
 * The package's central guarantee: if a scanner throws, the upload is REJECTED,
 * never silently accepted (fail closed). The orchestrator resolves scanners from
 * the container, so we bind throwing doubles to force the exception path on an
 * otherwise-benign file and assert it is still rejected.
 */
class FailClosedTest extends TestCase
{
    /**
     * @return array<int, mixed> the failure messages produced (empty = the rule passed)
     */
    private function runRule(UploadedFile $file): array
    {
        $messages = [];
        (new Safeguard())->validate('file', $file, function ($message) use (&$messages) {
            $messages[] = $message;
        });

        return $messages;
    }

    public function test_throwing_php_code_scanner_blocks_an_otherwise_benign_upload(): void
    {
        $this->app->bind(PhpCodeScanner::class, fn () => new class extends PhpCodeScanner
        {
            public function scan(UploadedFile|string $file): array
            {
                throw new \RuntimeException('scanner boom');
            }
        });

        // "hello world" would normally pass; a throwing scanner must NOT fail open.
        $messages = $this->runRule($this->uploadedFile('hello world', 'note.txt'));
        $this->assertNotEmpty($messages, 'A throwing PHP code scanner must reject the upload, not pass it.');
    }

    public function test_throwing_svg_scanner_blocks_an_otherwise_benign_upload(): void
    {
        $this->app->bind(SvgScanner::class, fn () => new class extends SvgScanner
        {
            public function scan(UploadedFile|string $file): array
            {
                throw new \RuntimeException('svg boom');
            }
        });

        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>';
        $messages = $this->runRule($this->uploadedFile($svg, 'art.svg'));
        $this->assertNotEmpty($messages, 'A throwing SVG scanner must reject the upload, not pass it.');
    }
}
