<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\SecurityLogger;
use Abdian\UploadGuard\SvgScanner;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * SafeguardSvg — sanitizes SVG uploads (allowlist), storing the cleaned output.
 */
class SafeguardSvg implements ValidationRule
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
        if (! $this->cfg('safeguard.svg_scanning.enabled', true)) {
            return;
        }

        $scanner = new SvgScanner();
        $result = $scanner->scan($file);

        if (! $result['safe']) {
            $this->report($file, SecurityLogger::EVENT_SVG_XSS, SecurityLogger::LEVEL_HIGH, $result['threats']);
            $fail($this->message($attribute, 'contains unsafe SVG content and cannot be uploaded', $result['threats'], $this->showThreats));

            return;
        }

        // Persist the sanitized output so the stored SVG is the cleaned version.
        $mode = (string) $this->cfg('safeguard.svg_scanning.mode', 'sanitize');
        if ($mode !== 'reject' && $result['clean'] !== null && $result['modified']) {
            $scanner->sanitizeFile($file);
        }
    }

    public function withThreats(): self
    {
        $this->showThreats = true;

        return $this;
    }
}
