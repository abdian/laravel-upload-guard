<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\Concerns\ValidatesFileAccess;
use Abdian\UploadGuard\Tests\TestCase;

class FileAccessTest extends TestCase
{
    private object $harness;

    protected function setUp(): void
    {
        parent::setUp();
        $this->harness = new class
        {
            use ValidatesFileAccess {
                validateFileAccess as public;
                validateDestinationPath as public;
            }
        };
    }

    public function test_sibling_prefix_directory_is_rejected(): void
    {
        $base = $this->scratchPath('app');
        @mkdir($base, 0700, true);
        $evil = $this->scratchPath('app-evil');
        @mkdir($evil, 0700, true);
        $evilFile = $evil . DIRECTORY_SEPARATOR . 'x.txt';
        file_put_contents($evilFile, 'x');

        config(['safeguard.security.allowed_upload_paths' => [$base]]);

        $this->assertFalse($this->harness->validateFileAccess($evilFile));
    }

    public function test_file_inside_allowed_dir_is_accepted(): void
    {
        $base = $this->scratchPath('allowed');
        @mkdir($base, 0700, true);
        $ok = $base . DIRECTORY_SEPARATOR . 'ok.txt';
        file_put_contents($ok, 'x');

        config(['safeguard.security.allowed_upload_paths' => [$base]]);

        $this->assertTrue($this->harness->validateFileAccess($ok));
    }

    public function test_empty_allow_list_fails_closed(): void
    {
        $f = $this->scratchPath('e.txt');
        file_put_contents($f, 'x');
        config(['safeguard.security.allowed_upload_paths' => []]);

        $this->assertFalse($this->harness->validateFileAccess($f));
    }

    public function test_null_byte_path_handled_without_error(): void
    {
        // Must return false (not throw a ValueError) and not reach realpath().
        $this->assertFalse($this->harness->validateFileAccess("/tmp/evil\0.php"));
    }

    public function test_destination_traversal_rejected(): void
    {
        $base = $this->scratchPath('dest');
        @mkdir($base, 0700, true);
        config(['safeguard.security.allowed_upload_paths' => [$base]]);

        $this->assertFalse($this->harness->validateDestinationPath($base . '/../escape.txt', [$base]));
        $this->assertTrue($this->harness->validateDestinationPath($base . '/file.txt', [$base]));
    }
}
