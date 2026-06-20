<?php

namespace Abdian\UploadGuard\Support;

use enshrined\svgSanitize\data\AttributeInterface;

final class SvgAllowedAttributes implements AttributeInterface
{
    /** @var array<string> */
    public static array $attributes = [];

    /**
     * @return array<string>
     */
    public static function getAttributes(): array
    {
        return self::$attributes;
    }
}
