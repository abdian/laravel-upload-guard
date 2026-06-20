<?php

namespace Abdian\UploadGuard\Tests;

use Abdian\UploadGuard\SafeguardServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

/**
 * Base test case wiring the Safeguard service provider into a Testbench app.
 */
abstract class TestCase extends Orchestra
{
    /**
     * Register the package service provider.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            SafeguardServiceProvider::class,
        ];
    }

    /**
     * Absolute path to a working scratch directory for generated fixtures.
     */
    protected function scratchPath(string $name = ''): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'safeguard-tests';
        if (! is_dir($dir)) {
            mkdir($dir, 0700, true);
        }

        return $name === '' ? $dir : $dir . DIRECTORY_SEPARATOR . $name;
    }

    /**
     * Build a test UploadedFile from raw bytes.
     */
    protected function uploadedFile(string $bytes, string $name): \Illuminate\Http\UploadedFile
    {
        $path = $this->scratchPath('up-' . bin2hex(random_bytes(4)) . '-' . $name);
        file_put_contents($path, $bytes);

        return new \Illuminate\Http\UploadedFile($path, $name, null, null, true);
    }
}
