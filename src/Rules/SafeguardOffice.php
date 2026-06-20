<?php

namespace Abdian\UploadGuard\Rules;

use Abdian\UploadGuard\Concerns\InteractsWithUploads;
use Abdian\UploadGuard\OfficeScanner;
use Abdian\UploadGuard\SecurityLogger;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * SafeguardOffice — detects macros / OLE / ActiveX in Office documents
 * (OOXML and legacy OLE/CFB).
 */
class SafeguardOffice implements ValidationRule
{
    use InteractsWithUploads;

    protected ?bool $blockMacros = null;

    protected ?bool $blockActiveX = null;

    /**
     * @param  array<string>  $parameters
     */
    public function __construct(array $parameters = [])
    {
        foreach ($parameters as $param) {
            $param = strtolower((string) $param);
            if ($param === 'allow_macros') {
                $this->blockMacros = false;
            }
            if ($param === 'allow_activex') {
                $this->blockActiveX = false;
            }
        }
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $file = $this->uploadedFileOrFail($attribute, $value, $fail);
        if ($file === null) {
            return;
        }
        if (! $this->cfg('safeguard.office_scanning.enabled', true)) {
            return;
        }

        $scanner = new OfficeScanner();
        if ($this->blockMacros !== null) {
            $scanner->blockMacros($this->blockMacros);
        }
        if ($this->blockActiveX !== null) {
            $scanner->blockActiveX($this->blockActiveX);
        }

        $result = $scanner->scan($file);
        if (! $result['safe']) {
            $this->report($file, SecurityLogger::EVENT_MACRO_DETECTED, SecurityLogger::LEVEL_HIGH, $result['threats']);
            $fail($this->message($attribute, 'contains macros or active content and cannot be uploaded', $result['threats'], false));
        }
    }

    public function allowMacros(): self
    {
        $this->blockMacros = false;

        return $this;
    }

    public function allowActiveX(): self
    {
        $this->blockActiveX = false;

        return $this;
    }

    public function blockMacros(): self
    {
        $this->blockMacros = true;

        return $this;
    }

    public function blockActiveX(): self
    {
        $this->blockActiveX = true;

        return $this;
    }
}
