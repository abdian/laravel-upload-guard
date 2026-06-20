<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\PhpCodeScanner;
use Abdian\UploadGuard\SecurityLogger;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * SafeguardPhp — rejects uploads containing PHP/script code.
 *
 * Opener detection runs on every file regardless of type; the dangerous-function
 * layer only triggers inside actual PHP regions (see PhpCodeScanner).
 */
class SafeguardPhp implements ValidationRule
{
    use InteractsWithUploads;

    public function __construct(protected bool $showThreats = false)
    {
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $file = $this->uploadedFileOrFail($attribute, $value, $fail);
        if ($file === null) {
            return;
        }

        $result = (new PhpCodeScanner())->scan($file);
        if (! $result['safe']) {
            $this->report($file, SecurityLogger::EVENT_PHP_CODE, SecurityLogger::LEVEL_HIGH, $result['threats']);
            $fail($this->message($attribute, 'contains potentially malicious code and cannot be uploaded', $result['threats'], $this->showThreats));
        }
    }

    public function withThreats(): self
    {
        $this->showThreats = true;

        return $this;
    }
}
