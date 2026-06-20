<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\SecurityLogger;
use Abdian\UploadGuard\Tests\TestCase;
use Illuminate\Support\Facades\Log;

class SecurityLoggerTest extends TestCase
{
    public function test_crlf_in_string_is_sanitized(): void
    {
        $clean = SecurityLogger::sanitizeString("evil\r\nInjected: line\x1b[31m");
        $this->assertStringNotContainsString("\r", $clean);
        $this->assertStringNotContainsString("\n", $clean);
        $this->assertStringNotContainsString("\x1b", $clean);
    }

    public function test_long_string_is_capped(): void
    {
        $clean = SecurityLogger::sanitizeString(str_repeat('a', 5000));
        $this->assertLessThanOrEqual(513, mb_strlen($clean));
    }

    public function test_logging_does_not_throw_on_unresolved_path(): void
    {
        Log::spy();
        // A non-existent path must not crash hashing/logging.
        SecurityLogger::logFileEvent('/no/such/file.bin', SecurityLogger::EVENT_PHP_CODE, SecurityLogger::LEVEL_HIGH, 'test');
        $this->assertTrue(true);
    }

    public function test_misconfigured_channel_does_not_break(): void
    {
        config(['safeguard.logging.channel' => 'nonexistent-channel-xyz']);
        Log::spy();
        SecurityLogger::logThreat(SecurityLogger::EVENT_DANGEROUS_FILE, SecurityLogger::LEVEL_HIGH, 'msg');
        $this->assertTrue(true);
    }

    public function test_disabled_logging_is_silent(): void
    {
        config(['safeguard.logging.enabled' => false]);
        Log::spy();
        SecurityLogger::logThreat(SecurityLogger::EVENT_DANGEROUS_FILE, SecurityLogger::LEVEL_HIGH, 'msg');
        Log::shouldNotHaveReceived('log');
        $this->assertTrue(true);
    }
}
