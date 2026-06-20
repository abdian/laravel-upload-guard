<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\PdfScanner;
use Abdian\UploadGuard\SecurityLogger;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * SafeguardPdf — decodes and scans PDFs for active/dangerous content.
 */
class SafeguardPdf implements ValidationRule
{
    use InteractsWithUploads;

    protected bool $blockJavaScript = false;

    protected bool $blockExternalLinks = false;

    public function __construct(protected bool $showThreats = false)
    {
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $file = $this->uploadedFileOrFail($attribute, $value, $fail);
        if ($file === null) {
            return;
        }
        if (! $this->cfg('safeguard.pdf_scanning.enabled', true)) {
            return;
        }

        $result = (new PdfScanner())->scan($file);

        if (! $result['safe']) {
            $this->report($file, SecurityLogger::EVENT_PDF_THREAT, SecurityLogger::LEVEL_HIGH, $result['threats']);
            $fail($this->message($attribute, 'contains potentially malicious content and cannot be uploaded', $result['threats'], $this->showThreats));

            return;
        }

        if ($this->blockJavaScript && $result['has_javascript']) {
            $fail("The {$attribute} PDF contains JavaScript.");

            return;
        }

        if ($this->blockExternalLinks && $result['has_external_links']) {
            $fail("The {$attribute} PDF contains external links.");
        }
    }

    public function blockJavaScript(): self
    {
        $this->blockJavaScript = true;

        return $this;
    }

    public function blockExternalLinks(): self
    {
        $this->blockExternalLinks = true;

        return $this;
    }

    public function withThreats(): self
    {
        $this->showThreats = true;

        return $this;
    }
}
