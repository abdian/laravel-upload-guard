<?php

namespace Abdian\UploadGuard\Support;

use enshrined\svgSanitize\data\AttributeInterface;
use enshrined\svgSanitize\data\TagInterface;

/**
 * Optional custom allowlists for the SVG sanitizer.
 *
 * The sanitizer reads the allowlist via a STATIC interface method, so the
 * configured values are held statically and assigned just before sanitizing.
 */
final class SvgAllowedTags implements TagInterface
{
    /** @var array<string> */
    public static array $tags = [];

    /**
     * @return array<string>
     */
    public static function getTags(): array
    {
        return self::$tags;
    }
}
