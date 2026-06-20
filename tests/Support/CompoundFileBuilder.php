<?php

namespace Abdian\UploadGuard\Tests\Support;

/**
 * CompoundFileBuilder — emits a minimal but structurally valid OLE/CFB
 * (Compound File Binary, "D0CF11E0") container for tests.
 *
 * The directory is laid out as a flat list of entries (Root Entry plus one
 * entry per unique path component) chained through the FAT, which is enough for
 * a name-enumerating parser to discover storages such as "Workbook" or
 * "_VBA_PROJECT". Stream contents are not stored (detection is name-based).
 */
class CompoundFileBuilder
{
    private const SECTOR = 512;
    private const FREESECT = 0xFFFFFFFF;
    private const ENDOFCHAIN = 0xFFFFFFFE;
    private const FATSECT = 0xFFFFFFFD;
    private const NOSTREAM = 0xFFFFFFFF;

    /**
     * @param  array<string, string>  $paths  path => (ignored) contents
     */
    public static function build(array $paths): string
    {
        // Collect unique entry names with their type (storage vs stream).
        $entries = [['name' => 'Root Entry', 'type' => 5]];
        $seen = ['Root Entry' => true];

        foreach (array_keys($paths) as $path) {
            $segments = explode('/', $path);
            $last = count($segments) - 1;
            foreach ($segments as $i => $segment) {
                if ($segment === '' || isset($seen[$segment])) {
                    continue;
                }
                $seen[$segment] = true;
                $entries[] = ['name' => $segment, 'type' => $i === $last ? 2 : 1];
            }
        }

        // Directory entries are 128 bytes each, 4 per 512-byte sector.
        $perSector = self::SECTOR / 128;
        $dirSectorCount = (int) ceil(count($entries) / $perSector);

        // Layout: sector 0 = FAT, sectors 1..N = directory.
        $fat = array_fill(0, self::SECTOR / 4, self::FREESECT);
        $fat[0] = self::FATSECT;
        for ($i = 0; $i < $dirSectorCount; $i++) {
            $sector = 1 + $i;
            $fat[$sector] = ($i === $dirSectorCount - 1) ? self::ENDOFCHAIN : $sector + 1;
        }

        $header = self::header(firstDirSector: 1, fatSectorCount: 1, firstFatSector: 0);
        $fatSector = self::pad(self::packU32Array($fat), self::SECTOR);
        $directory = self::pad(self::directory($entries, $dirSectorCount * $perSector), $dirSectorCount * self::SECTOR);

        return $header . $fatSector . $directory;
    }

    private static function header(int $firstDirSector, int $fatSectorCount, int $firstFatSector): string
    {
        $h = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"; // signature
        $h .= str_repeat("\x00", 16);            // CLSID
        $h .= pack('v', 0x003E);                 // minor version
        $h .= pack('v', 0x0003);                 // major version (v3, 512-byte sectors)
        $h .= pack('v', 0xFFFE);                 // byte order LE
        $h .= pack('v', 0x0009);                 // sector shift (512)
        $h .= pack('v', 0x0006);                 // mini sector shift (64)
        $h .= str_repeat("\x00", 6);             // reserved
        $h .= pack('V', 0);                      // number of directory sectors (0 for v3)
        $h .= pack('V', $fatSectorCount);        // number of FAT sectors
        $h .= pack('V', $firstDirSector);        // first directory sector
        $h .= pack('V', 0);                      // transaction signature
        $h .= pack('V', 4096);                   // mini stream cutoff
        $h .= pack('V', self::ENDOFCHAIN);       // first mini FAT sector
        $h .= pack('V', 0);                      // number of mini FAT sectors
        $h .= pack('V', self::ENDOFCHAIN);       // first DIFAT sector
        $h .= pack('V', 0);                      // number of DIFAT sectors

        // DIFAT array: 109 entries.
        $difat = array_fill(0, 109, self::FREESECT);
        $difat[0] = $firstFatSector;
        $h .= self::packU32Array($difat);

        return self::pad($h, self::SECTOR);
    }

    /**
     * @param  array<int, array{name: string, type: int}>  $entries
     */
    private static function directory(array $entries, int $slots): string
    {
        $out = '';
        for ($i = 0; $i < $slots; $i++) {
            if (isset($entries[$i])) {
                $out .= self::directoryEntry($entries[$i]['name'], $entries[$i]['type']);
            } else {
                // Unallocated free entry (type 0) with NOSTREAM links.
                $out .= self::directoryEntry('', 0);
            }
        }

        return $out;
    }

    private static function directoryEntry(string $name, int $type): string
    {
        $utf16 = mb_convert_encoding($name, 'UTF-16LE', 'UTF-8');
        $utf16 .= "\x00\x00"; // null terminator
        $nameLen = strlen($utf16);
        $nameField = str_pad(substr($utf16, 0, 64), 64, "\x00");

        $e = $nameField;                       // 0:  name (64)
        $e .= pack('v', $type === 0 ? 0 : $nameLen); // 64: name length
        $e .= chr($type);                      // 66: object type
        $e .= chr(1);                          // 67: color (black)
        $e .= pack('V', self::NOSTREAM);       // 68: left sibling
        $e .= pack('V', self::NOSTREAM);       // 72: right sibling
        $e .= pack('V', self::NOSTREAM);       // 76: child
        $e .= str_repeat("\x00", 16);          // 80: CLSID
        $e .= pack('V', 0);                    // 96: state bits
        $e .= str_repeat("\x00", 8);           // 100: creation time
        $e .= str_repeat("\x00", 8);           // 108: modified time
        $e .= pack('V', self::ENDOFCHAIN);     // 116: starting sector
        $e .= pack('V', 0);                    // 120: stream size (low)
        $e .= pack('V', 0);                    // 124: stream size (high)

        return $e;
    }

    /** @param array<int, int> $values */
    private static function packU32Array(array $values): string
    {
        $out = '';
        foreach ($values as $v) {
            $out .= pack('V', $v);
        }

        return $out;
    }

    private static function pad(string $data, int $size): string
    {
        if (strlen($data) >= $size) {
            return $data;
        }

        return $data . str_repeat("\x00", $size - strlen($data));
    }
}
