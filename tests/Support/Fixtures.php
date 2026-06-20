<?php

namespace Abdian\UploadGuard\Tests\Support;

/**
 * Fixtures — programmatic generator for benign and malicious test inputs.
 *
 * Everything is produced as raw byte strings (never written as an executable
 * script on disk). Each malicious sample maps to a confirmed historical bypass
 * so the regression suite can assert it is now blocked.
 */
class Fixtures
{
    /**
     * Benign PHP opener used as the polyglot payload. It contains a real `<?php`
     * opening tag (which the scanner must flag) but no web-shell signature, so it
     * does not trip host antivirus when written inside archives during tests.
     */
    public const PHP_PAYLOAD = "\n<?php /* safeguard-test opener */ echo 1; ?>\n";

    /** A PHP file whose function layer must flag a dangerous function. */
    public static function phpDangerousFunction(): string
    {
        return "<?php\n\$decoded = base64_decode(\$input);\n\$result = gzinflate(\$decoded);\n";
    }

    /** A PHP file using dynamic dispatch (variable function) — needs tokenization. */
    public static function phpVariableFunction(): string
    {
        return "<?php\n\$fn = 'sys' . 'tem';\n\$fn(\$argument);\n";
    }

    /** A bare short-open-tag PHP file. */
    public static function phpShortTag(): string
    {
        return "stuff\n<?= \$value ?>\nmore";
    }

    // ---------------------------------------------------------------------
    // Benign images
    // ---------------------------------------------------------------------

    /** Real, GD-decodable PNG. */
    public static function png(int $width = 2, int $height = 2): string
    {
        return self::gdImage('png', $width, $height);
    }

    /** Real, GD-decodable JPEG. */
    public static function jpeg(int $width = 2, int $height = 2): string
    {
        return self::gdImage('jpeg', $width, $height);
    }

    /** Real, GD-decodable GIF. */
    public static function gif(int $width = 2, int $height = 2): string
    {
        return self::gdImage('gif', $width, $height);
    }

    /** Real, GD-decodable BMP (size@2, DIB@14 are valid). */
    public static function bmp(int $width = 2, int $height = 2): string
    {
        return self::gdImage('bmp', $width, $height);
    }

    /** JPEG carrying a PHP opener inside a COM (comment) segment. */
    public static function jpegWithCommentCode(): string
    {
        $jpeg = self::jpeg();
        $code = '<?php echo 1;';
        $com = "\xFF\xFE" . pack('n', strlen($code) + 2) . $code;

        // Insert the COM segment right after the SOI marker (first 2 bytes).
        return substr($jpeg, 0, 2) . $com . substr($jpeg, 2);
    }

    /** A valid GIF with one extra byte appended after its trailer. */
    public static function gifExtraTrailer(): string
    {
        return self::gif() . "\x3B";
    }

    /** A "BM"-prefixed blob that is NOT a valid BMP (for structural-validation tests). */
    public static function fakeBmpPrefix(): string
    {
        return 'BM' . str_repeat("\x00", 4) . 'this is not really a bitmap, just BM-prefixed text';
    }

    /** Render a small raster image via GD and return its bytes. */
    private static function gdImage(string $format, int $width, int $height): string
    {
        $img = imagecreatetruecolor($width, $height);
        $color = imagecolorallocate($img, 10, 160, 10);
        imagefilledrectangle($img, 0, 0, $width - 1, $height - 1, $color);

        ob_start();
        match ($format) {
            'png' => imagepng($img),
            'jpeg' => imagejpeg($img, null, 90),
            'gif' => imagegif($img),
            'bmp' => imagebmp($img),
        };
        $bytes = (string) ob_get_clean();
        imagedestroy($img);

        return $bytes;
    }

    private static function pngChunk(string $type, string $data): string
    {
        return pack('N', strlen($data)) . $type . $data . pack('N', crc32($type . $data));
    }

    /**
     * A tiny PNG header that DECLARES enormous dimensions (decompression bomb).
     * Only the signature + IHDR are present; no real pixel data.
     */
    public static function decompressionBombPng(int $w = 50000, int $h = 50000): string
    {
        $sig = "\x89PNG\r\n\x1a\n";
        $ihdrData = pack('N', $w) . pack('N', $h) . "\x08\x06\x00\x00\x00";

        return $sig . self::pngChunk('IHDR', $ihdrData);
    }

    // ---------------------------------------------------------------------
    // PHP polyglots (valid container header + appended PHP)
    // ---------------------------------------------------------------------

    public static function phpInJpeg(): string
    {
        return self::jpeg() . self::PHP_PAYLOAD;
    }

    public static function phpInPng(): string
    {
        return self::png() . self::PHP_PAYLOAD;
    }

    public static function phpInGif(): string
    {
        return self::gif() . self::PHP_PAYLOAD;
    }

    public static function phpInBmp(): string
    {
        return self::bmp() . self::PHP_PAYLOAD;
    }

    public static function phpInPdf(): string
    {
        return self::pdf() . self::PHP_PAYLOAD;
    }

    /** A %PDF + <?php polyglot that defeats all-in-one rules. */
    public static function pdfPhpPolyglot(): string
    {
        return "%PDF-1.4\n" . self::PHP_PAYLOAD . "%%EOF\n";
    }

    /** Arbitrary unknown binary (octet-stream) with an embedded PHP opener. */
    public static function phpInOctetStream(): string
    {
        return "\x00\x01\x02\x03RANDOMBINARY\xFF\xFE" . self::PHP_PAYLOAD;
    }

    public static function phpInZip(): string
    {
        return self::zip(['notes.txt' => "hello\n" . self::PHP_PAYLOAD]);
    }

    // ---------------------------------------------------------------------
    // Benign text / source files (must NOT be flagged by the function layer)
    // ---------------------------------------------------------------------

    public static function javascriptSource(): string
    {
        return "const x = require('fs');\nfunction system(cmd){ return eval(cmd); }\nexports.run = system;\n";
    }

    public static function pythonSource(): string
    {
        return "import os\n\ndef run(c):\n    return os.system(c)\n\neval('1+1')\n";
    }

    public static function csv(): string
    {
        return "name,command\nalice,system\nbob,exec\ncarol,\"eval(x)\"\n";
    }

    public static function markdown(): string
    {
        return "# Title\n\nUse `eval()` carefully and never call `system()` on user input.\n";
    }

    // ---------------------------------------------------------------------
    // SVG
    // ---------------------------------------------------------------------

    public static function benignSvg(): string
    {
        return '<?xml version="1.0" encoding="UTF-8"?>'
            . '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 10 10">'
            . '<rect x="0" y="0" width="10" height="10" fill="#0a0"/>'
            . '<circle cx="5" cy="5" r="3" fill="#fff"/>'
            . '</svg>';
    }

    /** Unquoted event handler — defeats quoted-attribute regexes. */
    public static function svgUnquotedHandler(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg" onload=alert(1)>'
            . '<rect onclick=alert(2) width="10" height="10"/></svg>';
    }

    /** Well-formed (quoted) event handler — sanitizer can parse and strip it. */
    public static function svgQuotedHandler(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">'
            . '<rect width="10" height="10" onclick="alert(2)"/></svg>';
    }

    /** Leading-whitespace javascript: URI. */
    public static function svgWhitespaceJsUri(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<a href=" javascript:alert(1)"><text>x</text></a></svg>';
    }

    /** External DTD with no internal subset (SYSTEM). */
    public static function svgExternalDtdSystem(): string
    {
        return '<?xml version="1.0"?>'
            . '<!DOCTYPE svg SYSTEM "file:///etc/passwd">'
            . '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>';
    }

    /** PUBLIC external DTD. */
    public static function svgExternalDtdPublic(): string
    {
        return '<?xml version="1.0"?>'
            . '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://attacker.example/evil.dtd">'
            . '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>';
    }

    public static function svgWithScript(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>';
    }

    // ---------------------------------------------------------------------
    // PDF
    // ---------------------------------------------------------------------

    /** Minimal valid 1-page PDF with no active content. */
    public static function pdf(): string
    {
        $objects = [
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
        ];

        $pdf = "%PDF-1.4\n";
        $offsets = [];
        foreach ($objects as $obj) {
            $offsets[] = strlen($pdf);
            $pdf .= $obj;
        }
        $xrefPos = strlen($pdf);
        $pdf .= "xref\n0 " . (count($objects) + 1) . "\n";
        $pdf .= "0000000000 65535 f \n";
        foreach ($offsets as $off) {
            $pdf .= sprintf("%010d 00000 n \n", $off);
        }
        $pdf .= "trailer\n<< /Size " . (count($objects) + 1) . " /Root 1 0 R >>\n";
        $pdf .= "startxref\n{$xrefPos}\n%%EOF\n";

        return $pdf;
    }

    /** PDF with /OpenAction launching JavaScript (uncompressed). */
    public static function pdfOpenActionJs(): string
    {
        return "%PDF-1.4\n"
            . "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n"
            . "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            . "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            . "4 0 obj\n<< /S /JavaScript /JS (app.alert\\('x'\\);) >>\nendobj\n"
            . "trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    }

    /** PDF where /JavaScript appears via hex-escaped name /J#61vaScript. */
    public static function pdfHexEscapedJsName(): string
    {
        return "%PDF-1.4\n"
            . "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /J#61vaScript /JS (x) >> >>\nendobj\n"
            . "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            . "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            . "trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    }

    /** PDF with /JavaScript inside a FlateDecode stream. */
    public static function pdfFlateJs(): string
    {
        $inner = "<< /S /JavaScript /JS (app.alert\\('compressed'\\);) >>";
        $compressed = gzcompress($inner, 9);

        return "%PDF-1.4\n"
            . "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n"
            . "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            . "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            . "4 0 obj\n<< /Filter /FlateDecode /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n"
            . "trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    }

    /**
     * PDF carrying many fake "/Type /Page" tokens but a real page tree of 1.
     */
    public static function pdfInjectedPageTokens(): string
    {
        $fake = str_repeat("% /Type /Page fake injected token\n", 50);

        return "%PDF-1.4\n"
            . $fake
            . "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            . "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            . "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            . "trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    }

    /** PDF whose /Producer contains an incidental "javascript.info" substring. */
    public static function pdfIncidentalSubstring(): string
    {
        return "%PDF-1.4\n"
            . "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            . "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            . "3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
            . "5 0 obj\n<< /Producer (see https://javascript.info for details) >>\nendobj\n"
            . "trailer\n<< /Root 1 0 R /Info 5 0 R >>\n%%EOF\n";
    }

    // ---------------------------------------------------------------------
    // ZIP / archives
    // ---------------------------------------------------------------------

    /**
     * Build a standard ZIP from [name => contents] (stored, real sizes).
     *
     * @param  array<string, string>  $entries
     */
    public static function zip(array $entries): string
    {
        return RawZipBuilder::stored($entries);
    }

    /** ZIP containing a path-traversal entry (forward slash). */
    public static function zipTraversal(): string
    {
        return RawZipBuilder::stored(['../../../shell.php' => self::PHP_PAYLOAD]);
    }

    /** ZIP with a path-traversal entry whose CONTENT is benign (no PHP opener). */
    public static function zipTraversalBenign(): string
    {
        return RawZipBuilder::stored(['../../../config.txt' => 'just some benign data']);
    }

    /** ZIP containing a backslash traversal entry (stored literally). */
    public static function zipBackslashTraversal(): string
    {
        return RawZipBuilder::stored(['..\\..\\evil.txt' => 'x']);
    }

    /** ZIP with a multi-level double extension. */
    public static function zipDoubleExtension(): string
    {
        return RawZipBuilder::stored(['shell.php.safe.txt' => self::PHP_PAYLOAD]);
    }

    /** ZIP with an NTFS ADS-style entry name. */
    public static function zipAdsEntry(): string
    {
        return RawZipBuilder::stored(['evil.php:.jpg' => self::PHP_PAYLOAD]);
    }

    /** ZIP whose dangerous extension is hidden behind trailing whitespace/dots. */
    public static function zipWhitespaceEntry(): string
    {
        return RawZipBuilder::stored(['evil.php   ' => self::PHP_PAYLOAD]);
    }

    /** ZIP containing a blocked server-side handler file. */
    public static function zipHtaccess(): string
    {
        return RawZipBuilder::stored(['.htaccess' => "AddType application/x-httpd-php .jpg\n"]);
    }

    /** ZIP containing a symlink entry. */
    public static function zipSymlink(): string
    {
        return RawZipBuilder::build([
            ['name' => 'link', 'data' => '/etc/passwd', 'method' => 'store', 'symlink' => true],
        ]);
    }

    /**
     * Classic zip bomb: one entry that decompresses to many MB of zeros but is
     * tiny on disk. Used with a lowered max_decompressed_size in tests.
     */
    public static function zipBomb(int $megabytes = 5): string
    {
        return RawZipBuilder::build([
            ['name' => 'bomb.bin', 'data' => str_repeat("\0", $megabytes * 1024 * 1024), 'method' => 'deflate'],
        ]);
    }

    /**
     * Forged-central-directory zip bomb: a real deflated entry whose declared
     * uncompressed size is a tiny lie, so size-trusting scanners under-count.
     */
    public static function zipForgedSize(int $megabytes = 5): string
    {
        return RawZipBuilder::build([
            [
                'name' => 'bomb.bin',
                'data' => str_repeat("\0", $megabytes * 1024 * 1024),
                'method' => 'deflate',
                'declaredSize' => 16,
            ],
        ]);
    }

    /** A nested archive: outer.zip contains inner.zip containing shell.php. */
    public static function zipNested(): string
    {
        $inner = RawZipBuilder::stored(['payload/shell.php' => self::PHP_PAYLOAD]);

        return RawZipBuilder::stored(['inner.zip' => $inner]);
    }

    // ---------------------------------------------------------------------
    // Office documents
    // ---------------------------------------------------------------------

    /** Benign DOCX-like OOXML container. */
    public static function docx(): string
    {
        return self::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
            'word/document.xml' => '<?xml version="1.0"?><document><body><p>hello</p></body></document>',
        ]);
    }

    /** DOCX with a VBA macro part declared via content-types + relationships. */
    public static function docxWithMacro(): string
    {
        return self::zip([
            '[Content_Types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabledTemplate.main+xml"/>'
                . '<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>',
            '_rels/.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
            'word/document.xml' => '<?xml version="1.0"?><document><body/></document>',
            'word/_rels/document.xml.rels' => '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                . '<Relationship Id="rId10" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>',
            'word/vbaProject.bin' => "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1macrobytes",
        ]);
    }

    /** DOCX with a lowercase [content_types].xml part name. */
    public static function docxLowercaseContentTypes(): string
    {
        return self::zip([
            '[content_types].xml' => '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                . '<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>',
            'word/document.xml' => '<?xml version="1.0"?><document/>',
            'word/vbaProject.bin' => "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1macro",
        ]);
    }

    /**
     * Minimal OLE/CFB compound file (magic D0CF11E0) carrying a "Macros"
     * storage and a stream whose bytes contain "Auto_Open".
     */
    public static function legacyOleMacroDoc(): string
    {
        return CompoundFileBuilder::build([
            'WordDocument' => "\x00\x00word body",
            'Macros/VBA/_VBA_PROJECT' => "Attribute VB_Name = \"Module1\"\nSub Auto_Open()\nShell \"calc\"\nEnd Sub\n",
        ]);
    }

    /** Minimal benign OLE/CFB document (no macro storage). */
    public static function legacyOleBenign(): string
    {
        return CompoundFileBuilder::build([
            'WordDocument' => "\x00\x00plain word body with no macros",
        ]);
    }

    // ---------------------------------------------------------------------
    // Misc real binaries used for MIME disambiguation tests
    // ---------------------------------------------------------------------

    /** A JAR (zip with META-INF/MANIFEST.MF). */
    public static function jar(): string
    {
        return self::zip([
            'META-INF/MANIFEST.MF' => "Manifest-Version: 1.0\nMain-Class: Evil\n",
            'Evil.class' => "\xCA\xFE\xBA\xBE\x00\x00\x00\x34",
        ]);
    }

    /** A real .xls OLE workbook (Workbook stream inside CFB). */
    public static function legacyXls(): string
    {
        return CompoundFileBuilder::build([
            'Workbook' => "\x09\x08\x10\x00\x00\x06\x05\x00excel workbook stream",
        ]);
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** Write bytes to a path and return that path. */
    public static function writeTo(string $path, string $bytes): string
    {
        file_put_contents($path, $bytes);

        return $path;
    }
}
