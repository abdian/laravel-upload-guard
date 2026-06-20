<?php

namespace Abdian\UploadGuard\Support;

/**
 * CompoundFile — a minimal, defensive reader for OLE/CFB ("D0CF11E0")
 * compound documents (legacy .doc/.xls/.ppt and Office VBA project containers).
 *
 * It parses the header, walks the FAT to follow the directory chain, and
 * enumerates directory entry names. That is enough to:
 *   - disambiguate OLE subtypes (Workbook -> xls, WordDocument -> doc, ...)
 *   - detect macro storages (Macros / VBA / _VBA_PROJECT) for Office scanning.
 *
 * Parsing is bounded and fails safe: any inconsistency makes the relevant
 * accessor report "could not be determined" so callers can fail closed.
 */
class CompoundFile
{
    public const SIGNATURE = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

    private const ENDOFCHAIN = 0xFFFFFFFE;
    private const FREESECT = 0xFFFFFFFF;
    private const MAX_SECTORS = 1_048_576; // hard guard against malformed chains

    /** @var resource */
    private $handle;

    private int $sectorSize;

    private int $fileSize;

    private bool $valid = false;

    /**
     * True when parsing was forced to stop early (truncated FAT/DIFAT chain or
     * an unreadable directory sector) so enumeration may be missing entries.
     * Callers must fail closed when this is set.
     */
    private bool $incomplete = false;

    /** @var array<int,int> */
    private array $fat = [];

    /** @var array<int,string>|null */
    private ?array $names = null;

    private function __construct($handle, int $fileSize)
    {
        $this->handle = $handle;
        $this->fileSize = $fileSize;
    }

    /**
     * Open a path as a compound file, or return null when it is not one.
     */
    public static function open(string $path): ?self
    {
        if (! is_file($path) || ! is_readable($path)) {
            return null;
        }

        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return null;
        }

        $size = @filesize($path);
        $self = new self($handle, $size === false ? 0 : $size);

        if (! $self->parseHeader()) {
            fclose($handle);

            return null;
        }

        return $self;
    }

    public function __destruct()
    {
        if (is_resource($this->handle)) {
            @fclose($this->handle);
        }
    }

    /** Quick signature check without full parsing. */
    public static function isCompoundFile(string $path): bool
    {
        $handle = @fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }
        $magic = fread($handle, 8);
        fclose($handle);

        return $magic === self::SIGNATURE;
    }

    private function parseHeader(): bool
    {
        $header = $this->readAt(0, 512);
        if ($header === null || strlen($header) < 76 || ! str_starts_with($header, self::SIGNATURE)) {
            return false;
        }

        $sectorShift = unpack('v', substr($header, 30, 2))[1];
        $this->sectorSize = 1 << $sectorShift;
        if ($this->sectorSize !== 512 && $this->sectorSize !== 4096) {
            return false;
        }

        $numFatSectors = unpack('V', substr($header, 44, 4))[1];
        $this->firstDirSector = unpack('V', substr($header, 48, 4))[1];
        $firstDifatSector = unpack('V', substr($header, 68, 4))[1];
        $numDifatSectors = unpack('V', substr($header, 72, 4))[1];

        // DIFAT: the 109 entries embedded in the header point at FAT sectors.
        $difat = [];
        for ($i = 0; $i < 109; $i++) {
            $sector = unpack('V', substr($header, 76 + $i * 4, 4))[1];
            if ($sector === self::FREESECT || $sector === self::ENDOFCHAIN) {
                continue;
            }
            $difat[] = $sector;
        }

        // Files with more than 109 FAT sectors store the rest of the DIFAT in a
        // sector chain. Each DIFAT sector holds (entriesPerSector - 1) FAT
        // sector pointers plus a trailing link to the next DIFAT sector. Failing
        // to follow this chain truncates the FAT and silently hides later
        // storages (fail-open), so build it fully and flag any break.
        $entriesPerSector = intdiv($this->sectorSize, 4);
        $difatSector = $firstDifatSector;
        $difatVisited = [];
        $difatChainCount = 0;
        while ($difatSector !== self::ENDOFCHAIN && $difatSector !== self::FREESECT) {
            if (isset($difatVisited[$difatSector]) || $difatChainCount > self::MAX_SECTORS) {
                $this->incomplete = true; // cycle or runaway chain
                break;
            }
            $difatVisited[$difatSector] = true;
            $difatChainCount++;

            $data = $this->readSector($difatSector);
            if ($data === null) {
                $this->incomplete = true; // truncated DIFAT chain
                break;
            }
            for ($i = 0; $i < $entriesPerSector - 1; $i++) {
                $sector = unpack('V', substr($data, $i * 4, 4))[1];
                if ($sector === self::FREESECT || $sector === self::ENDOFCHAIN) {
                    continue;
                }
                $difat[] = $sector;
            }
            // Last 4 bytes link to the next DIFAT sector.
            $difatSector = unpack('V', substr($data, ($entriesPerSector - 1) * 4, 4))[1];
        }

        // If the header advertises more FAT/DIFAT sectors than we managed to
        // resolve, enumeration cannot be trusted to be complete.
        if ($numFatSectors > 0 && count($difat) < $numFatSectors) {
            $this->incomplete = true;
        }
        if ($numDifatSectors > 0 && $difatChainCount < $numDifatSectors) {
            $this->incomplete = true;
        }

        // Build the FAT from every referenced FAT sector.
        foreach ($difat as $fatSector) {
            $data = $this->readSector($fatSector);
            if ($data === null) {
                $this->incomplete = true; // a referenced FAT sector is missing
                continue;
            }
            for ($i = 0; $i < $entriesPerSector; $i++) {
                $this->fat[] = unpack('V', substr($data, $i * 4, 4))[1];
            }
        }

        $this->valid = ! empty($this->fat) && $this->firstDirSector !== self::ENDOFCHAIN;

        return $this->valid;
    }

    private int $firstDirSector = self::ENDOFCHAIN;

    /**
     * Enumerate directory entry names (storages and streams).
     *
     * @return array<int,string>
     */
    public function entryNames(): array
    {
        if ($this->names !== null) {
            return $this->names;
        }

        $this->names = [];
        if (! $this->valid) {
            return $this->names;
        }

        $entriesPerSector = intdiv($this->sectorSize, 128);
        $sector = $this->firstDirSector;
        $visited = [];

        while ($sector !== self::ENDOFCHAIN && $sector >= 0 && $sector < self::MAX_SECTORS) {
            if (isset($visited[$sector])) {
                break; // cycle guard
            }
            $visited[$sector] = true;

            $data = $this->readSector($sector);
            if ($data === null) {
                // The directory chain is truncated: entries past this point
                // (which may include a macro storage) cannot be enumerated.
                $this->incomplete = true;
                break;
            }

            for ($i = 0; $i < $entriesPerSector; $i++) {
                $entry = substr($data, $i * 128, 128);
                if (strlen($entry) < 68) {
                    continue;
                }
                $nameLen = unpack('v', substr($entry, 64, 2))[1];
                $objType = ord($entry[66]);
                if ($objType === 0 || $nameLen < 2 || $nameLen > 64) {
                    continue;
                }
                $raw = substr($entry, 0, $nameLen - 2); // strip null terminator
                $name = @mb_convert_encoding($raw, 'UTF-8', 'UTF-16LE');
                if ($name !== false && $name !== '') {
                    $this->names[] = $name;
                }
            }

            $sector = $this->fat[$sector] ?? self::ENDOFCHAIN;
        }

        return $this->names;
    }

    /**
     * False when parsing had to stop early (truncated FAT/DIFAT chain or an
     * unreadable directory sector), meaning enumeration may be incomplete and
     * callers should fail closed. Enumeration is triggered if not yet done so
     * mid-chain truncation is observed.
     */
    public function isComplete(): bool
    {
        $this->entryNames();

        return ! $this->incomplete;
    }

    /** True if any directory entry indicates a VBA/macro storage. */
    public function hasMacroStorage(): bool
    {
        foreach ($this->entryNames() as $name) {
            $lower = strtolower(trim($name));
            if (in_array($lower, ['macros', 'vba', '_vba_project', 'vbaproject', 'project', 'projectwm'], true)) {
                return true;
            }
            if (str_contains($lower, 'vba')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Best-effort OLE subtype from storage names. Returns a MIME type or null.
     */
    public function detectOleSubtype(): ?string
    {
        $names = array_map(static fn ($n) => strtolower($n), $this->entryNames());

        foreach ($names as $name) {
            if ($name === 'workbook' || $name === 'book') {
                return 'application/vnd.ms-excel';
            }
            if ($name === 'worddocument') {
                return 'application/msword';
            }
            if ($name === 'powerpoint document') {
                return 'application/vnd.ms-powerpoint';
            }
            if ($name === '__properties' && in_array('__nameid_version1.0', $names, true)) {
                return 'application/vnd.ms-outlook';
            }
        }

        // Has a recognizable Office stream but unknown subtype.
        return null;
    }

    private function readSector(int $sector): ?string
    {
        if ($sector < 0 || $sector >= self::MAX_SECTORS) {
            return null;
        }
        $offset = ($sector + 1) * $this->sectorSize;

        return $this->readAt($offset, $this->sectorSize);
    }

    private function readAt(int $offset, int $length): ?string
    {
        if ($offset < 0 || ($this->fileSize > 0 && $offset >= $this->fileSize)) {
            return null;
        }
        if (fseek($this->handle, $offset) !== 0) {
            return null;
        }
        $data = fread($this->handle, $length);

        return $data === false ? null : $data;
    }
}
