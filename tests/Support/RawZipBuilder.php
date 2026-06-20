<?php

namespace Abdian\UploadGuard\Tests\Support;

/**
 * RawZipBuilder — emits ZIP bytes directly (local headers + central directory)
 * so tests can embed entry names that ZipArchive refuses to write (path
 * traversal, NTFS ADS, trailing whitespace), forge declared sizes, and mark
 * entries as symlinks. Supports store and deflate methods.
 */
class RawZipBuilder
{
    /**
     * @param  array<int, array{name:string,data?:string,method?:string,symlink?:bool,declaredSize?:int}>  $entries
     */
    public static function build(array $entries): string
    {
        $local = '';
        $central = '';
        $offset = 0;

        foreach ($entries as $entry) {
            $name = $entry['name'];
            $data = $entry['data'] ?? '';
            $method = $entry['method'] ?? 'store';
            $symlink = $entry['symlink'] ?? false;

            $crc = crc32($data);
            $uncompressed = strlen($data);

            if ($method === 'deflate') {
                $compressed = gzdeflate($data, 9);
                $methodCode = 8;
            } else {
                $compressed = $data;
                $methodCode = 0;
            }
            $compSize = strlen($compressed);

            // Optionally forge the declared uncompressed size.
            $declaredSize = $entry['declaredSize'] ?? $uncompressed;

            $nameBytes = $name;
            $nameLen = strlen($nameBytes);

            // Local file header.
            $lfh = "PK\x03\x04";
            $lfh .= pack('v', 20);            // version needed
            $lfh .= pack('v', 0);             // flags
            $lfh .= pack('v', $methodCode);   // method
            $lfh .= pack('v', 0);             // mod time
            $lfh .= pack('v', 0);             // mod date
            $lfh .= pack('V', $crc);
            $lfh .= pack('V', $compSize);
            $lfh .= pack('V', $declaredSize);
            $lfh .= pack('v', $nameLen);
            $lfh .= pack('v', 0);             // extra len
            $lfh .= $nameBytes;

            $localOffset = $offset;
            $local .= $lfh . $compressed;
            $offset += strlen($lfh) + $compSize;

            // External attributes: mark symlinks via the unix mode high word.
            $externalAttr = $symlink ? (0xA1FF << 16) : 0;

            // Central directory header.
            $cdh = "PK\x01\x02";
            $cdh .= pack('v', 0x031E);        // version made by (unix)
            $cdh .= pack('v', 20);            // version needed
            $cdh .= pack('v', 0);             // flags
            $cdh .= pack('v', $methodCode);
            $cdh .= pack('v', 0);             // mod time
            $cdh .= pack('v', 0);             // mod date
            $cdh .= pack('V', $crc);
            $cdh .= pack('V', $compSize);
            $cdh .= pack('V', $declaredSize);
            $cdh .= pack('v', $nameLen);
            $cdh .= pack('v', 0);             // extra len
            $cdh .= pack('v', 0);             // comment len
            $cdh .= pack('v', 0);             // disk number start
            $cdh .= pack('v', 0);             // internal attrs
            $cdh .= pack('V', $externalAttr); // external attrs
            $cdh .= pack('V', $localOffset);
            $cdh .= $nameBytes;

            $central .= $cdh;
        }

        $centralOffset = strlen($local);
        $eocd = "PK\x05\x06";
        $eocd .= pack('v', 0);                       // disk number
        $eocd .= pack('v', 0);                       // disk with central dir
        $eocd .= pack('v', count($entries));         // entries on this disk
        $eocd .= pack('v', count($entries));         // total entries
        $eocd .= pack('V', strlen($central));        // central dir size
        $eocd .= pack('V', $centralOffset);          // central dir offset
        $eocd .= pack('v', 0);                       // comment length

        return $local . $central . $eocd;
    }

    /**
     * Convenience builder for plain stored entries.
     *
     * @param  array<string, string>  $nameToData
     */
    public static function stored(array $nameToData): string
    {
        $entries = [];
        foreach ($nameToData as $name => $data) {
            $entries[] = ['name' => $name, 'data' => $data, 'method' => 'store'];
        }

        return self::build($entries);
    }
}
