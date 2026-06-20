<?php

namespace Abdian\UploadGuard;

/**
 * ExtensionMimeMap - Maps file extensions to their valid MIME types
 *
 * This class provides a strict mapping between file extensions and MIME types,
 * enabling the safeguard rule to work with Laravel's native 'mimes' rule.
 *
 * Key Features:
 * - Converts Laravel mimes extensions (jpg, png, pdf) to full MIME types
 * - Enforces strict extension-to-MIME matching (prevents extension spoofing)
 * - Supports all common file types used in web applications
 */
class ExtensionMimeMap
{
    /**
     * Extension to MIME type mapping
     * Each extension maps to an array of valid MIME types
     *
     * @var array<string, array<string>>
     */
    protected static array $extensionToMime = [
        // Images
        'jpg' => ['image/jpeg'],
        'jpeg' => ['image/jpeg'],
        'jpe' => ['image/jpeg'],
        'png' => ['image/png'],
        'gif' => ['image/gif'],
        'bmp' => ['image/bmp', 'image/x-ms-bmp'],
        'ico' => ['image/x-icon', 'image/vnd.microsoft.icon'],
        'tiff' => ['image/tiff'],
        'tif' => ['image/tiff'],
        'svg' => ['image/svg+xml'],
        'svgz' => ['image/svg+xml'],
        'webp' => ['image/webp'],
        'avif' => ['image/avif'],
        'heic' => ['image/heic'],
        'heif' => ['image/heif'],

        // Documents - PDF
        'pdf' => ['application/pdf'],

        // Documents - Microsoft Office (Legacy OLE/CFB)
        'doc' => ['application/msword', 'application/x-ole-storage'],
        'dot' => ['application/msword', 'application/x-ole-storage'],
        'xls' => ['application/vnd.ms-excel', 'application/x-ole-storage'],
        'xlt' => ['application/vnd.ms-excel', 'application/x-ole-storage'],
        'ppt' => ['application/vnd.ms-powerpoint', 'application/x-ole-storage'],
        'pot' => ['application/vnd.ms-powerpoint', 'application/x-ole-storage'],
        'pps' => ['application/vnd.ms-powerpoint', 'application/x-ole-storage'],
        'msg' => ['application/vnd.ms-outlook', 'application/x-ole-storage'],

        // Documents - Microsoft Office (Open XML)
        'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
        'dotx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.template'],
        'docm' => ['application/vnd.ms-word.document.macroEnabled.12'],
        'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
        'xltx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.template'],
        'xlsm' => ['application/vnd.ms-excel.sheet.macroEnabled.12'],
        'pptx' => ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
        'potx' => ['application/vnd.openxmlformats-officedocument.presentationml.template'],
        'ppsx' => ['application/vnd.openxmlformats-officedocument.presentationml.slideshow'],
        'pptm' => ['application/vnd.ms-powerpoint.presentation.macroEnabled.12'],

        // Documents - OpenDocument
        'odt' => ['application/vnd.oasis.opendocument.text'],
        'ods' => ['application/vnd.oasis.opendocument.spreadsheet'],
        'odp' => ['application/vnd.oasis.opendocument.presentation'],
        'odg' => ['application/vnd.oasis.opendocument.graphics'],

        // Documents - Text
        'txt' => ['text/plain'],
        'csv' => ['text/csv', 'text/plain', 'application/csv'],
        'rtf' => ['application/rtf', 'text/rtf'],

        // Archives
        'zip' => ['application/zip', 'application/x-zip-compressed'],
        'rar' => ['application/x-rar-compressed', 'application/vnd.rar'],
        '7z' => ['application/x-7z-compressed'],
        'tar' => ['application/x-tar'],
        'gz' => ['application/gzip', 'application/x-gzip'],
        'tgz' => ['application/gzip', 'application/x-gzip'],
        'bz2' => ['application/x-bzip2'],
        'xz' => ['application/x-xz'],
        'jar' => ['application/java-archive'],
        'apk' => ['application/vnd.android.package-archive'],
        'epub' => ['application/epub+zip'],

        // Audio
        'mp3' => ['audio/mpeg', 'audio/mp3'],
        'wav' => ['audio/wav', 'audio/x-wav'],
        'ogg' => ['audio/ogg', 'application/ogg'],
        'flac' => ['audio/flac'],
        'aac' => ['audio/aac'],
        'm4a' => ['audio/mp4', 'audio/x-m4a'],
        'wma' => ['audio/x-ms-wma', 'video/x-ms-asf'],

        // Video
        'mp4' => ['video/mp4'],
        'avi' => ['video/x-msvideo'],
        'wmv' => ['video/x-ms-wmv', 'video/x-ms-asf'],
        'asf' => ['video/x-ms-asf'],
        'mov' => ['video/quicktime'],
        'mkv' => ['video/x-matroska'],
        'webm' => ['video/webm'],
        'flv' => ['video/x-flv'],
        'm4v' => ['video/x-m4v'],
        'mpeg' => ['video/mpeg'],
        'mpg' => ['video/mpeg'],

        // Web
        'html' => ['text/html'],
        'htm' => ['text/html'],
        'css' => ['text/css'],
        'js' => ['application/javascript', 'text/javascript'],
        'json' => ['application/json'],
        'xml' => ['application/xml', 'text/xml'],

        // Fonts
        'ttf' => ['font/ttf', 'application/x-font-ttf'],
        'otf' => ['font/otf', 'application/x-font-otf'],
        'woff' => ['font/woff', 'application/font-woff'],
        'woff2' => ['font/woff2'],
        'eot' => ['application/vnd.ms-fontobject'],
    ];

    /**
     * MIME type to extensions mapping (reverse lookup)
     * Lazily generated from extensionToMime
     *
     * @var array<string, array<string>>|null
     */
    protected static ?array $mimeToExtension = null;

    /**
     * Get MIME types for a given extension
     *
     * @param string $extension File extension (without dot)
     * @return array<string> Array of valid MIME types, empty if unknown
     */
    public static function getMimeTypes(string $extension): array
    {
        $extension = strtolower(ltrim($extension, '.'));
        return self::$extensionToMime[$extension] ?? [];
    }

    /**
     * Get the primary (first) MIME type for an extension
     *
     * @param string $extension File extension (without dot)
     * @return string|null Primary MIME type or null if unknown
     */
    public static function getPrimaryMimeType(string $extension): ?string
    {
        $mimeTypes = self::getMimeTypes($extension);
        return $mimeTypes[0] ?? null;
    }

    /**
     * Get valid extensions for a given MIME type
     *
     * @param string $mimeType The MIME type
     * @return array<string> Array of valid extensions
     */
    public static function getExtensions(string $mimeType): array
    {
        self::buildMimeToExtensionMap();
        $mimeType = strtolower($mimeType);
        return self::$mimeToExtension[$mimeType] ?? [];
    }

    /**
     * Check if an extension is valid for a given MIME type
     *
     * @param string $extension File extension (without dot)
     * @param string $mimeType The MIME type to check against
     * @return bool True if the extension is valid for this MIME type
     */
    public static function isValidExtensionForMime(string $extension, string $mimeType): bool
    {
        $extension = strtolower(ltrim($extension, '.'));
        $mimeType = strtolower($mimeType);

        $validMimeTypes = self::getMimeTypes($extension);
        return in_array($mimeType, $validMimeTypes);
    }

    /**
     * Check if a MIME type is valid for a given extension
     *
     * @param string $mimeType The MIME type
     * @param string $extension File extension (without dot)
     * @return bool True if the MIME type is valid for this extension
     */
    public static function isValidMimeForExtension(string $mimeType, string $extension): bool
    {
        return self::isValidExtensionForMime($extension, $mimeType);
    }

    /**
     * Convert an array of extensions to their MIME types
     * Used to convert Laravel's mimes rule parameters to safeguard_mime parameters
     *
     * @param array<string> $extensions Array of file extensions
     * @return array<string> Array of unique MIME types
     */
    public static function extensionsToMimeTypes(array $extensions): array
    {
        $mimeTypes = [];

        foreach ($extensions as $extension) {
            $mimes = self::getMimeTypes($extension);
            foreach ($mimes as $mime) {
                if (!in_array($mime, $mimeTypes)) {
                    $mimeTypes[] = $mime;
                }
            }
        }

        return $mimeTypes;
    }

    /**
     * Check if extension is known/supported
     *
     * @param string $extension File extension (without dot)
     * @return bool True if extension is known
     */
    public static function isKnownExtension(string $extension): bool
    {
        $extension = strtolower(ltrim($extension, '.'));
        return isset(self::$extensionToMime[$extension]);
    }

    /**
     * Get all supported extensions
     *
     * @return array<string> Array of all supported extensions
     */
    public static function getAllExtensions(): array
    {
        return array_keys(self::$extensionToMime);
    }

    /**
     * Add custom extension to MIME mapping
     *
     * @param string $extension File extension (without dot)
     * @param array<string> $mimeTypes Array of valid MIME types
     * @return void
     */
    public static function addMapping(string $extension, array $mimeTypes): void
    {
        $extension = strtolower(ltrim($extension, '.'));
        self::$extensionToMime[$extension] = $mimeTypes;
        self::$mimeToExtension = null; // Reset reverse map
    }

    /**
     * Build the reverse MIME to extension map
     *
     * @return void
     */
    protected static function buildMimeToExtensionMap(): void
    {
        if (self::$mimeToExtension !== null) {
            return;
        }

        self::$mimeToExtension = [];

        foreach (self::$extensionToMime as $extension => $mimeTypes) {
            foreach ($mimeTypes as $mimeType) {
                $mimeType = strtolower($mimeType);
                if (!isset(self::$mimeToExtension[$mimeType])) {
                    self::$mimeToExtension[$mimeType] = [];
                }
                if (!in_array($extension, self::$mimeToExtension[$mimeType])) {
                    self::$mimeToExtension[$mimeType][] = $extension;
                }
            }
        }
    }
}
