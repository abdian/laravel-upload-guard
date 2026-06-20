<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\PdfScanner;
use Abdian\UploadGuard\SecurityLogger;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * SafeguardPages — validates a PDF's page count against min/max bounds.
 *
 * Page counting is authoritative (catalog page tree, after inflation). An
 * indeterminate count skips the check and logs rather than hard-failing the
 * upload (availability-only check).
 */
class SafeguardPages implements ValidationRule
{
    use InteractsWithUploads;

    public function __construct(protected ?int $minPages = null, protected ?int $maxPages = null)
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

        $count = (new PdfScanner())->pageCount($file);

        // Indeterminate count: skip + log instead of hard-failing.
        if ($count === null) {
            SecurityLogger::logThreat(
                SecurityLogger::EVENT_PAGE_EXCEEDED,
                SecurityLogger::LEVEL_LOW,
                'PDF page count could not be determined; page check skipped',
                ['attribute' => $attribute]
            );

            return;
        }

        if ($this->minPages !== null && $count < $this->minPages) {
            $fail("The {$attribute} must have at least {$this->minPages} page(s). It has {$count}.");

            return;
        }
        if ($this->maxPages !== null && $count > $this->maxPages) {
            $fail("The {$attribute} must not exceed {$this->maxPages} page(s). It has {$count}.");
        }
    }

    public function min(int $pages): self
    {
        $this->minPages = $pages;

        return $this;
    }

    public function max(int $pages): self
    {
        $this->maxPages = $pages;

        return $this;
    }

    public function exactly(int $pages): self
    {
        $this->minPages = $pages;
        $this->maxPages = $pages;

        return $this;
    }
}
