<?php

namespace Abdian\UploadGuard\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Http\UploadedFile;

/**
 * SafeguardDimensions - Validates image dimensions (width and height)
 *
 * This validation rule checks actual image dimensions to prevent:
 * - Excessively large images (memory/bandwidth issues)
 * - Images smaller than required (quality issues)
 * - Aspect ratio violations
 *
 * Usage:
 *   'avatar' => ['required', new SafeguardDimensions(1920, 1080)]
 *   'avatar' => ['required', new SafeguardDimensions(maxWidth: 1920, maxHeight: 1080)]
 *
 * Or via string rule:
 *   'avatar' => 'required|safeguard_dimensions:1920,1080'
 *   'avatar' => 'required|safeguard_dimensions:1920,1080,800,600'  // max_w,max_h,min_w,min_h
 */
class SafeguardDimensions implements ValidationRule
{
    /**
     * Maximum width in pixels
     *
     * @var int|null
     */
    protected ?int $maxWidth;

    /**
     * Maximum height in pixels
     *
     * @var int|null
     */
    protected ?int $maxHeight;

    /**
     * Minimum width in pixels
     *
     * @var int|null
     */
    protected ?int $minWidth;

    /**
     * Minimum height in pixels
     *
     * @var int|null
     */
    protected ?int $minHeight;

    /**
     * Required aspect ratio (width/height)
     *
     * @var float|null
     */
    protected ?float $aspectRatio;

    /**
     * Aspect ratio tolerance
     *
     * @var float
     */
    protected float $aspectRatioTolerance = 0.01;

    /**
     * Create a new rule instance
     *
     * @param int|null $maxWidth Maximum width in pixels
     * @param int|null $maxHeight Maximum height in pixels
     * @param int|null $minWidth Minimum width in pixels
     * @param int|null $minHeight Minimum height in pixels
     */
    public function __construct(
        ?int $maxWidth = null,
        ?int $maxHeight = null,
        ?int $minWidth = null,
        ?int $minHeight = null
    ) {
        $this->maxWidth = $maxWidth;
        $this->maxHeight = $maxHeight;
        $this->minWidth = $minWidth;
        $this->minHeight = $minHeight;
        $this->aspectRatio = null;
    }

    /**
     * Run the validation rule
     *
     * @param string $attribute The attribute name being validated
     * @param mixed $value The value to validate (should be UploadedFile)
     * @param Closure $fail Callback to call if validation fails
     * @return void
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        // Check if value is an uploaded file
        if (!$value instanceof UploadedFile) {
            $fail("The {$attribute} must be a valid uploaded file.");
            return;
        }

        // Check if file was uploaded successfully
        if (!$value->isValid()) {
            $fail("The {$attribute} upload failed.");
            return;
        }

        // Get image dimensions
        $dimensions = @getimagesize($value->getRealPath());

        if ($dimensions === false) {
            $fail("The {$attribute} is not a valid image file or dimensions cannot be determined.");
            return;
        }

        [$width, $height] = $dimensions;

        // Check maximum width
        if ($this->maxWidth !== null && $width > $this->maxWidth) {
            $fail("The {$attribute} width must not exceed {$this->maxWidth} pixels. Current: {$width}px.");
            return;
        }

        // Check maximum height
        if ($this->maxHeight !== null && $height > $this->maxHeight) {
            $fail("The {$attribute} height must not exceed {$this->maxHeight} pixels. Current: {$height}px.");
            return;
        }

        // Check minimum width
        if ($this->minWidth !== null && $width < $this->minWidth) {
            $fail("The {$attribute} width must be at least {$this->minWidth} pixels. Current: {$width}px.");
            return;
        }

        // Check minimum height
        if ($this->minHeight !== null && $height < $this->minHeight) {
            $fail("The {$attribute} height must be at least {$this->minHeight} pixels. Current: {$height}px.");
            return;
        }

        // Check aspect ratio
        if ($this->aspectRatio !== null) {
            $currentRatio = $width / $height;
            $difference = abs($currentRatio - $this->aspectRatio);

            if ($difference > $this->aspectRatioTolerance) {
                $expectedRatio = number_format($this->aspectRatio, 2);
                $actualRatio = number_format($currentRatio, 2);
                $fail("The {$attribute} aspect ratio must be {$expectedRatio}. Current: {$actualRatio}.");
                return;
            }
        }
    }

    /**
     * Set required aspect ratio
     *
     * @param float $ratio Aspect ratio (width/height)
     * @param float $tolerance Tolerance for aspect ratio
     * @return self
     */
    public function ratio(float $ratio, float $tolerance = 0.01): self
    {
        $this->aspectRatio = $ratio;
        $this->aspectRatioTolerance = $tolerance;
        return $this;
    }

    /**
     * Set square requirement (1:1 aspect ratio)
     *
     * @return self
     */
    public function square(): self
    {
        return $this->ratio(1.0);
    }

    /**
     * Set minimum dimensions
     *
     * @param int $width Minimum width
     * @param int $height Minimum height
     * @return self
     */
    public function min(int $width, int $height): self
    {
        $this->minWidth = $width;
        $this->minHeight = $height;
        return $this;
    }

    /**
     * Set maximum dimensions
     *
     * @param int $width Maximum width
     * @param int $height Maximum height
     * @return self
     */
    public function max(int $width, int $height): self
    {
        $this->maxWidth = $width;
        $this->maxHeight = $height;
        return $this;
    }
}
