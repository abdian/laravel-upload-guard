<?php

namespace Abdian\UploadGuard;

use Abdian\UploadGuard\Concerns\ValidatesFileAccess;
use Abdian\UploadGuard\Support\CompoundFile;
use Illuminate\Http\UploadedFile;
use ZipArchive;

/**
 * OfficeScanner — detects macros / OLE objects / ActiveX in Office documents.
 *
 * Covers BOTH:
 *   - OOXML (zip) — parts are located case-insensitively and VBA/OLE/ActiveX are
 *     resolved via [Content_Types].xml content types and OPC .rels relationship
 *     types (not hard-coded filenames), so renamed VBA storages are still caught;
 *   - legacy OLE/CFB (.doc/.xls/.ppt) — macro storages are detected by walking
 *     the compound-file directory.
 *
 * Fails closed: when macro blocking is enabled and a container cannot be fully
 * parsed, the document is rejected. Explicit fluent flags (allowMacros(), …) are
 * never overwritten by configuration.
 */
class OfficeScanner
{
    use ValidatesFileAccess;

    protected ?bool $blockMacros = null;

    protected ?bool $blockActiveX = null;

    protected array $regularExtensions = ['docx', 'xlsx', 'pptx', 'dotx', 'xltx', 'potx'];

    /**
     * @return array{safe: bool, threats: array<string>, has_macros: bool, has_activex: bool}
     */
    public function scan(UploadedFile|string $file): array
    {
        $path = $file instanceof UploadedFile ? $file->getRealPath() : $file;
        $originalName = $file instanceof UploadedFile ? (string) $file->getClientOriginalName() : basename((string) $path);

        if ($path === false || $path === '' || ! is_file($path) || ! is_readable($path)) {
            return $this->failResult(['File cannot be read']);
        }
        if (! $this->validateFileAccess($path)) {
            return $this->failResult([$this->getFileAccessFailureReason($path)]);
        }

        if ($this->isRtf($path)) {
            return $this->scanRtf($path);
        }

        if ($this->isLegacyOfficeFormat($path)) {
            return $this->scanLegacy($path);
        }

        if ($this->isZip($path)) {
            return $this->scanOoxml($path, $originalName);
        }

        // Not an Office container — nothing for this scanner to assess.
        return ['safe' => true, 'threats' => [], 'has_macros' => false, 'has_activex' => false];
    }

    /**
     * @return array{safe: bool, threats: array<string>, has_macros: bool, has_activex: bool}
     */
    protected function scanLegacy(string $path): array
    {
        $cf = CompoundFile::open($path);
        if ($cf === null) {
            // Unparsable compound file: fail closed if we block macros.
            if ($this->effectiveBlockMacros()) {
                return $this->failResult(['Unparsable legacy Office container']);
            }

            return ['safe' => true, 'threats' => [], 'has_macros' => false, 'has_activex' => false];
        }

        // Incomplete enumeration (e.g. a truncated FAT/DIFAT chain) means a macro
        // storage could be hidden past the point we stopped reading. Fail closed.
        if (! $cf->isComplete() && $this->effectiveBlockMacros()) {
            return $this->failResult(['Legacy Office container could not be fully parsed']);
        }

        $hasMacros = $cf->hasMacroStorage();
        $threats = [];
        if ($hasMacros && $this->effectiveBlockMacros()) {
            $threats[] = 'VBA macro storage detected in legacy Office document';
        }

        return [
            'safe' => $threats === [],
            'threats' => $threats,
            'has_macros' => $hasMacros,
            'has_activex' => false,
        ];
    }

    /**
     * @return array{safe: bool, threats: array<string>, has_macros: bool, has_activex: bool}
     */
    protected function scanOoxml(string $path, string $originalName): array
    {
        $zip = new ZipArchive();
        if ($zip->open($path, ZipArchive::RDONLY) !== true) {
            // A zip-shaped Office file we cannot open: fail closed when blocking.
            if ($this->effectiveBlockMacros()) {
                return $this->failResult(['Office document could not be opened']);
            }

            return ['safe' => true, 'threats' => [], 'has_macros' => false, 'has_activex' => false];
        }

        $threats = [];
        $contentTypes = $this->readContentTypes($zip);
        $relationshipTypes = $this->collectRelationshipTypes($zip);
        $partNames = $this->collectPartNames($zip);

        // --- Macros (VBA) -------------------------------------------------
        $hasMacros = $this->detectVba($contentTypes, $relationshipTypes, $partNames);
        if ($hasMacros && $this->effectiveBlockMacros()) {
            $threats[] = 'VBA macro detected';
        }

        // --- ActiveX / embedded OLE objects -------------------------------
        $hasActiveX = $this->detectActiveXOrOle($contentTypes, $relationshipTypes, $partNames);
        if ($hasActiveX && $this->effectiveBlockActiveX()) {
            $threats[] = 'ActiveX control or embedded OLE object detected';
        }

        // --- DDE / DDEAUTO field-code injection (macro-less code execution) -
        // Treated as active content under macro blocking, even with no VBA.
        if ($this->effectiveBlockMacros() && $this->detectDdeFieldCodes($zip)) {
            $hasMacros = true;
            $threats[] = 'DDE/DDEAUTO field code detected (active content)';
        }

        // --- Remote-template / external OLE injection ---------------------
        // External relationships (attachedTemplate, oleObject, frame,
        // subDocument with TargetMode="External") pull remote content at open
        // time and are treated as active content under macro blocking.
        if ($this->effectiveBlockMacros() && $this->detectExternalActiveRelationships($zip)) {
            $hasMacros = true;
            $threats[] = 'External active relationship detected (remote template/OLE injection)';
        }

        $zip->close();

        // Extension spoofing: macro content under a non-macro extension.
        $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
        $allowedMacroExt = (array) $this->getOfficeConfig('allowed_macro_extensions', []);
        $regular = array_diff($this->regularExtensions, $allowedMacroExt);
        if ($hasMacros && $this->effectiveBlockMacros() && in_array($extension, $regular, true)) {
            $threats[] = "Macro-enabled content disguised as .{$extension}";
        }

        return [
            'safe' => $threats === [],
            'threats' => array_values(array_unique($threats)),
            'has_macros' => $hasMacros,
            'has_activex' => $hasActiveX,
        ];
    }

    private function readContentTypes(ZipArchive $zip): string
    {
        $index = $zip->locateName('[Content_Types].xml', ZipArchive::FL_NOCASE);
        if ($index === false) {
            return '';
        }
        $data = $zip->getFromIndex($index);

        return $data === false ? '' : $data;
    }

    /**
     * @return array<string>
     */
    private function collectRelationshipTypes(ZipArchive $zip): array
    {
        $types = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            if ($name === false || ! str_ends_with(strtolower($name), '.rels')) {
                continue;
            }
            $data = $zip->getFromIndex($i);
            if ($data === false) {
                continue;
            }
            if (preg_match_all('/Type\s*=\s*"([^"]+)"/i', $data, $m)) {
                foreach ($m[1] as $type) {
                    $types[] = strtolower($type);
                }
            }
        }

        return $types;
    }

    /**
     * @return array<string>
     */
    private function collectPartNames(ZipArchive $zip): array
    {
        $names = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            if ($name !== false) {
                $names[] = strtolower($name);
            }
        }

        return $names;
    }

    /**
     * @param  array<string>  $relationshipTypes
     * @param  array<string>  $partNames
     */
    private function detectVba(string $contentTypes, array $relationshipTypes, array $partNames): bool
    {
        $ct = strtolower($contentTypes);
        if (str_contains($ct, 'vbaproject') || str_contains($ct, 'macroenabled')) {
            return true;
        }
        foreach ($relationshipTypes as $type) {
            if (str_contains($type, 'vbaproject')) {
                return true;
            }
        }
        foreach ($partNames as $name) {
            if (str_contains($name, 'vbaproject.bin') || str_ends_with($name, 'vbadata.xml') || str_contains($name, 'vbaproject')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string>  $relationshipTypes
     * @param  array<string>  $partNames
     */
    private function detectActiveXOrOle(string $contentTypes, array $relationshipTypes, array $partNames): bool
    {
        $ct = strtolower($contentTypes);
        if (str_contains($ct, 'activex') || str_contains($ct, 'oleobject')) {
            return true;
        }
        foreach ($relationshipTypes as $type) {
            if (str_contains($type, 'control') || str_contains($type, 'oleobject') || str_contains($type, 'package')) {
                return true;
            }
        }
        foreach ($partNames as $name) {
            if (preg_match('#activex/activex\d*\.(xml|bin)#', $name) || preg_match('#embeddings/oleobject\d*\.bin#', $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect DDE / DDEAUTO field codes (and DDE spreadsheet formulas) anywhere
     * they can be hosted in an OOXML package. These run external commands at
     * open time without any VBA.
     *
     * DDE-bearing active content is not confined to word/document.xml:
     *   - WordprocessingML field codes are evaluated in any document story part
     *     (footnotes, endnotes, comments, headers, footers, glossary) and the
     *     "main" part name is resolved through the OPC officeDocument
     *     relationship, so it can be renamed (e.g. word/main.xml or even
     *     story/main.xml outside word/);
     *   - SpreadsheetML cells can carry a DDE call as a formula
     *     (<f>=cmd|'/c calc.exe'!A1</f>) in any xl/ worksheet part.
     * Restricting to a fixed list of part names — or to the word/ prefix — is
     * therefore an allowlist bypass. Instead inspect EVERY XML part (any *.xml
     * excluding .rels and the content-type manifest) and flag a DDE token that
     * appears inside an actual active-content context (Word field code or
     * spreadsheet formula) so incidental substrings elsewhere do not
     * over-trigger.
     */
    private function detectDdeFieldCodes(ZipArchive $zip): bool
    {
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            if ($name === false) {
                continue;
            }
            $lower = strtolower($name);
            if (! str_ends_with($lower, '.xml')) {
                continue;
            }
            // Relationship parts and the content-type manifest never host field
            // codes or formulas; skip them so we do not over-trigger.
            if (str_ends_with($lower, '.rels') || $lower === '[content_types].xml') {
                continue;
            }
            $data = $zip->getFromIndex($i);
            if ($data === false) {
                // A part we expected to inspect is unreadable: be conservative.
                return true;
            }
            // WordprocessingML field codes carry DDE/DDEAUTO either as a
            // w:fldSimple w:instr attribute or as text inside <w:instrText>.
            // Require a field-code context so an incidental "dde" substring does
            // not over-trigger. The main story part may be renamed and may live
            // outside word/, so this is checked on every XML part.
            if (preg_match('/\bDDE(AUTO)?\b/i', $data) && (
                preg_match('/<[^>]*\bw:instr\s*=\s*"[^"]*\bDDE(AUTO)?\b/i', $data)
                || preg_match('/<w:instrText\b[^>]*>[^<]*\bDDE(AUTO)?\b/i', $data)
            )) {
                return true;
            }
            // SpreadsheetML DDE: a cell formula <f>…</f> (or shared formula)
            // that issues a DDE call. The classic payload begins a DDE server
            // reference (e.g. =cmd|'/c calc.exe'!A1) or uses the DDE()/DDEAUTO
            // worksheet functions. Only worksheet/formula parts (xl/) carry
            // <f> formula elements, so scope the formula check there.
            if (str_contains($lower, 'xl/') && $this->hasDdeSpreadsheetFormula($data)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Inspect every <f>…</f> formula element in a SpreadsheetML part and flag
     * any whose (entity-decoded) text issues a DDE call: a leading server
     * reference of the form server|'topic'!item (e.g. cmd|'/c calc.exe'!A1)
     * or the DDE()/DDEAUTO worksheet functions.
     */
    private function hasDdeSpreadsheetFormula(string $data): bool
    {
        if (! preg_match_all('/<f\b[^>]*>(.*?)<\/f>/is', $data, $m)) {
            return false;
        }
        foreach ($m[1] as $formula) {
            $f = html_entity_decode($formula, ENT_QUOTES | ENT_XML1);
            // Excel strips a leading '=' from the stored formula but tolerate it.
            $f = ltrim($f);
            $f = ltrim($f, '=');
            if (preg_match('/\bDDE(AUTO)?\s*\(/i', $f)) {
                return true;
            }
            // DDE server reference: <name>|'<topic>'!<item>, e.g. cmd|'/c …'!A1.
            // The bar between an executable/server token and a quoted topic is
            // the hallmark of a DDE call placed in a cell formula.
            if (preg_match("/[A-Za-z0-9_.\\\\\\/ :-]*\\|\\s*['\"][^'\"]*['\"]\\s*!/", $f)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect OPC relationships with TargetMode="External" whose Type pulls
     * remote active content (attachedTemplate / oleObject / frame /
     * subDocument), i.e. remote-template injection.
     */
    private function detectExternalActiveRelationships(ZipArchive $zip): bool
    {
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            if ($name === false || ! str_ends_with(strtolower($name), '.rels')) {
                continue;
            }
            $data = $zip->getFromIndex($i);
            if ($data === false) {
                continue;
            }
            if (! preg_match_all('/<Relationship\b[^>]*>/i', $data, $m)) {
                continue;
            }
            foreach ($m[0] as $rel) {
                if (! preg_match('/TargetMode\s*=\s*"External"/i', $rel)) {
                    continue;
                }
                if (! preg_match('/Type\s*=\s*"([^"]*)"/i', $rel, $tm)) {
                    continue;
                }
                $type = strtolower($tm[1]);
                if (str_contains($type, 'attachedtemplate')
                    || str_contains($type, 'oleobject')
                    || str_contains($type, 'frame')
                    || str_contains($type, 'subdocument')) {
                    return true;
                }
            }
        }

        return false;
    }

    public function isOfficeDocument(string $path): bool
    {
        if (! is_file($path)) {
            return false;
        }
        if ($this->isRtf($path)) {
            return true;
        }
        if ($this->isLegacyOfficeFormat($path)) {
            $cf = CompoundFile::open($path);

            // Route any CFB with a recognized OLE subtype OR a macro storage. A
            // macro-bearing compound file with no document-type stream (subtype
            // null) is still dangerous and must be routed to the scanner.
            return $cf !== null && ($cf->detectOleSubtype() !== null || $cf->hasMacroStorage());
        }
        if (! $this->isZip($path)) {
            return false;
        }

        $zip = new ZipArchive();
        if ($zip->open($path, ZipArchive::RDONLY) !== true) {
            return false;
        }
        $hasContentTypes = $zip->locateName('[Content_Types].xml', ZipArchive::FL_NOCASE) !== false;
        $hasOfficeDir = $zip->locateName('word/', ZipArchive::FL_NOCASE) !== false
            || $zip->locateName('word/document.xml', ZipArchive::FL_NOCASE) !== false
            || $zip->locateName('xl/workbook.xml', ZipArchive::FL_NOCASE) !== false
            || $zip->locateName('ppt/presentation.xml', ZipArchive::FL_NOCASE) !== false;
        $zip->close();

        return $hasContentTypes && $hasOfficeDir;
    }

    public function isLegacyOfficeFormat(string $path): bool
    {
        return CompoundFile::isCompoundFile($path);
    }

    private function isZip(string $path): bool
    {
        $head = @file_get_contents($path, false, null, 0, 4);

        return $head !== false && (str_starts_with($head, "PK\x03\x04") || str_starts_with($head, "PK\x05\x06"));
    }

    private function isRtf(string $path): bool
    {
        $head = @file_get_contents($path, false, null, 0, 16);

        return $head !== false && str_starts_with(ltrim($head), '{\rtf');
    }

    /**
     * RTF stores embedded OLE objects as hex-encoded \objdata and can carry
     * DDE field codes. An embedded/linked/auto-updating OLE object (the classic
     * "Packager" phishing-to-RCE technique) and DDEAUTO fields are active content,
     * so flag them when macro blocking is on.
     *
     * @return array{safe: bool, threats: array<string>, has_macros: bool, has_activex: bool}
     */
    private function scanRtf(string $path): array
    {
        if (! $this->effectiveBlockMacros()) {
            return ['safe' => true, 'threats' => [], 'has_macros' => false, 'has_activex' => false];
        }

        $content = @file_get_contents($path, false, null, 0, 16 * 1024 * 1024);
        if ($content === false) {
            return $this->failResult(['RTF document could not be read']);
        }

        if (preg_match('/\\\\obj(?:data|emb|link|autlink|update)\b/i', $content)
            || preg_match('/\bDDE(?:AUTO)?\b/', $content)) {
            return [
                'safe' => false,
                'threats' => ['RTF contains an embedded OLE object or DDE field (active content)'],
                'has_macros' => true,
                'has_activex' => false,
            ];
        }

        return ['safe' => true, 'threats' => [], 'has_macros' => false, 'has_activex' => false];
    }

    public function blockMacros(bool $block = true): self
    {
        $this->blockMacros = $block;

        return $this;
    }

    public function blockActiveX(bool $block = true): self
    {
        $this->blockActiveX = $block;

        return $this;
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

    private function effectiveBlockMacros(): bool
    {
        return $this->blockMacros ?? (bool) $this->getOfficeConfig('block_macros', true);
    }

    private function effectiveBlockActiveX(): bool
    {
        return $this->blockActiveX ?? (bool) $this->getOfficeConfig('block_activex', true);
    }

    /**
     * @return array{safe: bool, threats: array<string>, has_macros: bool, has_activex: bool}
     */
    protected function failResult(array $threats): array
    {
        return ['safe' => false, 'threats' => $threats, 'has_macros' => false, 'has_activex' => false];
    }

    protected function getOfficeConfig(string $key, mixed $default = null): mixed
    {
        if (function_exists('config') && function_exists('app')) {
            try {
                $value = config("safeguard.office_scanning.{$key}", $default);

                return $value ?? $default;
            } catch (\Throwable) {
                return $default;
            }
        }

        return $default;
    }
}
