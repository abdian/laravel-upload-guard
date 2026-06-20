<?php

namespace Abdian\UploadGuard\Tests\Unit;

use Abdian\UploadGuard\ArchiveScanner;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\Support\RawZipBuilder;
use Abdian\UploadGuard\Tests\TestCase;

class ArchiveScannerTest extends TestCase
{
    private ArchiveScanner $scanner;

    protected function setUp(): void
    {
        parent::setUp();
        $this->scanner = new ArchiveScanner();
    }

    private function scan(string $bytes, string $name = 'a.zip'): array
    {
        $path = $this->scratchPath($name);
        Fixtures::writeTo($path, $bytes);

        return $this->scanner->scan($path);
    }

    public function test_benign_zip_passes(): void
    {
        $result = $this->scan(Fixtures::docx(), 'ok.zip');
        $this->assertTrue($result['safe'], implode(',', $result['threats']));
    }

    public function test_forward_slash_traversal_blocked(): void
    {
        $this->assertFalse($this->scan(Fixtures::zipTraversal())['safe']);
    }

    public function test_backslash_traversal_blocked(): void
    {
        $this->assertFalse($this->scan(Fixtures::zipBackslashTraversal())['safe']);
    }

    public function test_multilevel_double_extension_blocked(): void
    {
        $this->assertFalse($this->scan(Fixtures::zipDoubleExtension())['safe']);
    }

    public function test_ntfs_ads_entry_blocked(): void
    {
        $this->assertFalse($this->scan(Fixtures::zipAdsEntry())['safe']);
    }

    public function test_trailing_whitespace_extension_blocked(): void
    {
        $this->assertFalse($this->scan(Fixtures::zipWhitespaceEntry())['safe']);
    }

    public function test_blocked_handler_file(): void
    {
        $this->assertFalse($this->scan(Fixtures::zipHtaccess())['safe']);
    }

    public function test_symlink_entry_blocked(): void
    {
        $this->assertFalse($this->scan(Fixtures::zipSymlink())['safe']);
    }

    public function test_classic_zip_bomb_blocked(): void
    {
        config(['safeguard.archive_scanning.max_decompressed_size' => 1024 * 1024]);
        $result = $this->scan(Fixtures::zipBomb(5));
        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(array_filter($result['threats'], fn ($t) => str_contains($t, 'bomb')));
    }

    public function test_forged_central_directory_size_bomb_blocked(): void
    {
        config(['safeguard.archive_scanning.max_decompressed_size' => 1024 * 1024]);
        $result = $this->scan(Fixtures::zipForgedSize(5));
        $this->assertFalse($result['safe'], 'Forged declared size must not bypass streaming detection');
    }

    public function test_nested_archive_is_recursed(): void
    {
        $result = $this->scan(Fixtures::zipNested());
        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(array_filter($result['threats'], fn ($t) => str_contains($t, 'Nested')));
    }

    public function test_unsupported_format_rejected(): void
    {
        // 7z magic with junk — cannot be stream-inspected, must be rejected.
        $bytes = "7z\xBC\xAF\x27\x1C" . str_repeat("\x00", 64);
        $this->assertFalse($this->scan($bytes, 'x.7z')['safe']);
    }

    /**
     * EXACT bypass: the decompression cap used to be PER-ARCHIVE — every nested
     * zip got a fresh full budget — so a tree where NO single archive exceeds
     * the cap could still decompress to a global total far above it. The budget
     * is now GLOBAL across the whole nesting tree and must flag this as a bomb.
     */
    public function test_global_decompression_budget_across_nested_tree_blocked(): void
    {
        // Each inner zip decompresses one 100 KiB chunk (well under the cap on
        // its own); five of them sum to ~500 KiB, far above the 300 KiB cap.
        config(['safeguard.archive_scanning.max_decompressed_size' => 300 * 1024]);

        $chunk = str_repeat("\0", 100 * 1024);
        $entries = [];
        for ($i = 0; $i < 5; $i++) {
            $inner = RawZipBuilder::build([
                ['name' => "chunk{$i}.bin", 'data' => $chunk, 'method' => 'deflate'],
            ]);
            // Store the inner zips so the outer archive stays tiny on disk; the
            // bomb only materializes once each inner archive is decompressed.
            $entries[] = ['name' => "inner{$i}.zip", 'data' => $inner, 'method' => 'store'];
        }
        $outer = RawZipBuilder::build($entries);

        $result = $this->scan($outer, 'tree.zip');
        $this->assertFalse($result['safe'], 'Global decompression total exceeds the cap and must be flagged');
        $this->assertNotEmpty(
            array_filter($result['threats'], fn ($t) => str_contains($t, 'bomb')),
            'A decompression bomb threat must be reported'
        );
    }

    /**
     * Benign control: the same nested shape, but the global decompressed total
     * stays comfortably under the cap, so it must pass.
     */
    public function test_benign_nested_archive_under_global_budget_passes(): void
    {
        config(['safeguard.archive_scanning.max_decompressed_size' => 1024 * 1024]);

        $entries = [];
        for ($i = 0; $i < 3; $i++) {
            $inner = RawZipBuilder::build([
                ['name' => "note{$i}.txt", 'data' => str_repeat('a', 4 * 1024), 'method' => 'deflate'],
            ]);
            $entries[] = ['name' => "inner{$i}.zip", 'data' => $inner, 'method' => 'store'];
        }
        $outer = RawZipBuilder::build($entries);

        $result = $this->scan($outer, 'benign-tree.zip');
        $this->assertTrue($result['safe'], implode(',', $result['threats']));
    }

    /**
     * EXACT bypass: a TAR entry header declaring a body size that runs past EOF
     * used to be fseek()'d over blindly (trusting the declared size). It must
     * now be treated as a threat instead.
     */
    public function test_tar_oversized_declared_size_blocked(): void
    {
        $tar = $this->buildTar('big.bin', 100 * 1024 * 1024, ''); // declares 100 MiB, no body
        $result = $this->scan($tar, 'x.tar');
        $this->assertFalse($result['safe']);
        $this->assertNotEmpty(
            array_filter($result['threats'], fn ($t) => str_contains($t, 'past end') || str_contains($t, 'bomb')),
            'An oversized/desyncing TAR declared size must be flagged'
        );
    }

    // ---------------------------------------------------------------------
    // Confirmed bypass regressions (red-team).
    // ---------------------------------------------------------------------

    /**
     * BYPASS 2: a PHP webshell DEFLATE-compressed inside a zip used to pass
     * because only entry names + sizes were inspected, never the decompressed
     * bytes. The decompressed content must now be code-scanned.
     */
    public function test_deflated_php_webshell_in_zip_blocked(): void
    {
        $zip = RawZipBuilder::build([
            ['name' => 'uploads/avatar.txt', 'data' => '<?php system($_GET[0]); ?>', 'method' => 'deflate'],
        ]);
        $result = $this->scan($zip, 'shell.zip');
        $this->assertFalse($result['safe'], 'A deflated PHP webshell inside a zip must be flagged');
        $this->assertNotEmpty(
            array_filter($result['threats'], fn ($t) => str_contains($t, 'Embedded code')),
            implode(',', $result['threats'])
        );
    }

    /**
     * BYPASS 2 (gzip): a .gz whose INFLATED content is a PHP webshell must be
     * flagged on the decompressed bytes.
     */
    public function test_gzipped_php_webshell_blocked(): void
    {
        $gz = gzencode('<?php system($_GET["c"]); ?>', 9);
        $result = $this->scan($gz, 'shell.gz');
        $this->assertFalse($result['safe'], 'A gzipped PHP webshell must be flagged');
        $this->assertNotEmpty(
            array_filter($result['threats'], fn ($t) => str_contains($t, 'Embedded code')),
            implode(',', $result['threats'])
        );
    }

    /**
     * BYPASS 3a: scanTar() read only name[0..100] and ignored the 155-byte
     * ustar PREFIX (offset 345). A traversal hidden in the prefix
     * (../../../../etc + cron.d/pwn) must now be resolved and rejected.
     */
    public function test_tar_ustar_prefix_traversal_blocked(): void
    {
        $tar = $this->buildTarWithPrefix('cron.d/pwn', '../../../../etc', 'x');
        $result = $this->scan($tar, 'prefix.tar');
        $this->assertFalse($result['safe'], 'A ustar prefix-encoded traversal must be flagged');
        $this->assertNotEmpty(
            array_filter($result['threats'], fn ($t) => str_contains($t, 'traversal')),
            implode(',', $result['threats'])
        );
    }

    /**
     * BYPASS 3b: a GNU LongLink/LongName ('L') extended header holds the real
     * long pathname for the NEXT entry while the stub name is benign. The real
     * name (uploads/.htaccess) must be resolved and rejected.
     */
    public function test_tar_gnu_longname_blocked_filename(): void
    {
        $tar = $this->buildTarWithLongName('innocent.txt', 'uploads/.htaccess', 'x');
        $result = $this->scan($tar, 'longname.tar');
        $this->assertFalse($result['safe'], 'A GNU LongName-hidden blocked filename must be flagged');
        $this->assertNotEmpty(
            array_filter($result['threats'], fn ($t) => str_contains($t, 'Blocked filename') || str_contains($t, 'htaccess')),
            implode(',', $result['threats'])
        );
    }

    /**
     * BYPASS 1: a threat wrapped beyond max_nesting_depth used to return null
     * (treated as SAFE). A traversal entry wrapped 4 levels deep (cap = 3) must
     * now fail closed.
     */
    public function test_threat_wrapped_beyond_max_depth_blocked(): void
    {
        config(['safeguard.archive_scanning.max_nesting_depth' => 3]);

        // Innermost: a traversal entry that the recursion never reaches.
        $level0 = RawZipBuilder::build([
            ['name' => '../../../../etc/passwd', 'data' => 'x', 'method' => 'store'],
        ]);
        $bytes = $level0;
        for ($i = 0; $i < 4; $i++) {
            $bytes = RawZipBuilder::build([
                ['name' => "layer{$i}.zip", 'data' => $bytes, 'method' => 'store'],
            ]);
        }

        $result = $this->scan($bytes, 'deep.zip');
        $this->assertFalse($result['safe'], 'A threat nested beyond the depth cap must fail closed');
        $this->assertNotEmpty(
            array_filter($result['threats'], fn ($t) => str_contains($t, 'depth') || str_contains($t, 'traversal')),
            implode(',', $result['threats'])
        );
    }

    /**
     * Benign control: a real ustar tar with a clean name passes.
     */
    public function test_benign_tar_passes(): void
    {
        $tar = $this->buildTar('readme.txt', 5, 'hello');
        $result = $this->scan($tar, 'ok.tar');
        $this->assertTrue($result['safe'], implode(',', $result['threats']));
    }

    /**
     * Benign control: a nested zip whose deepest entry is clean (within depth
     * cap) still passes.
     */
    public function test_benign_nested_zip_passes(): void
    {
        $inner = RawZipBuilder::build([
            ['name' => 'note.txt', 'data' => 'hello world', 'method' => 'deflate'],
        ]);
        $outer = RawZipBuilder::build([
            ['name' => 'inner.zip', 'data' => $inner, 'method' => 'store'],
        ]);
        $result = $this->scan($outer, 'benign-nested.zip');
        $this->assertTrue($result['safe'], implode(',', $result['threats']));
    }

    /**
     * Build a ustar entry that uses the 155-byte PREFIX field (offset 345) so
     * the real path is prefix + '/' + name.
     */
    private function buildTarWithPrefix(string $name, string $prefix, string $body): string
    {
        $header = $this->tarHeader($name, strlen($body), '0', '', $prefix);
        $padded = str_pad($body, (int) (ceil(strlen($body) / 512) * 512), "\0");

        return $header . $padded . str_repeat("\0", 1024);
    }

    /**
     * Build a GNU LongName ('L') extended header whose DATA block holds the
     * real long pathname, followed by a stub entry carrying $stubName.
     */
    private function buildTarWithLongName(string $stubName, string $longName, string $body): string
    {
        $longData = $longName . "\0";
        $longHeader = $this->tarHeader('././@LongLink', strlen($longData), 'L', '', '');
        $longBlock = $longHeader . str_pad($longData, (int) (ceil(strlen($longData) / 512) * 512), "\0");

        $stubHeader = $this->tarHeader($stubName, strlen($body), '0', '', '');
        $padded = str_pad($body, (int) (ceil(strlen($body) / 512) * 512), "\0");

        return $longBlock . $stubHeader . $padded . str_repeat("\0", 1024);
    }

    /**
     * Construct a single 512-byte ustar header with a valid checksum.
     */
    private function tarHeader(string $name, int $size, string $typeflag, string $linkname, string $prefix): string
    {
        $header = str_repeat("\0", 512);
        $header = substr_replace($header, $name, 0, strlen($name));
        $header = substr_replace($header, sprintf('%07o', 0o644) . "\0", 100, 8);
        $header = substr_replace($header, sprintf('%07o', 0) . "\0", 108, 8);
        $header = substr_replace($header, sprintf('%07o', 0) . "\0", 116, 8);
        $header = substr_replace($header, sprintf('%011o', $size) . "\0", 124, 12);
        $header = substr_replace($header, sprintf('%011o', 0) . "\0", 136, 12);
        $header = substr_replace($header, $typeflag, 156, 1);
        if ($linkname !== '') {
            $header = substr_replace($header, $linkname, 157, strlen($linkname));
        }
        $header = substr_replace($header, "ustar\x0000", 257, 8);
        if ($prefix !== '') {
            $header = substr_replace($header, $prefix, 345, strlen($prefix));
        }

        $header = substr_replace($header, str_repeat(' ', 8), 148, 8);
        $sum = 0;
        for ($i = 0; $i < 512; $i++) {
            $sum += ord($header[$i]);
        }
        $header = substr_replace($header, sprintf('%06o', $sum) . "\0 ", 148, 8);

        return $header;
    }

    /**
     * Build a single-entry ustar archive with a (possibly forged) declared size
     * but an actual body of $body, padded to a 512-byte block.
     */
    private function buildTar(string $name, int $declaredSize, string $body): string
    {
        $header = str_repeat("\0", 512);
        $header = substr_replace($header, $name, 0, strlen($name));
        $header = substr_replace($header, sprintf('%07o', 0o644) . "\0", 100, 8);   // mode
        $header = substr_replace($header, sprintf('%07o', 0) . "\0", 108, 8);       // uid
        $header = substr_replace($header, sprintf('%07o', 0) . "\0", 116, 8);       // gid
        $header = substr_replace($header, sprintf('%011o', $declaredSize) . "\0", 124, 12); // size
        $header = substr_replace($header, sprintf('%011o', 0) . "\0", 136, 12);     // mtime
        $header = substr_replace($header, '0', 156, 1);                              // typeflag (file)
        $header = substr_replace($header, "ustar\x0000", 257, 8);                    // magic + version

        // Checksum: spaces during computation, then octal value.
        $header = substr_replace($header, str_repeat(' ', 8), 148, 8);
        $sum = 0;
        for ($i = 0; $i < 512; $i++) {
            $sum += ord($header[$i]);
        }
        $header = substr_replace($header, sprintf('%06o', $sum) . "\0 ", 148, 8);

        $padded = $body === '' ? '' : str_pad($body, (int) (ceil(strlen($body) / 512) * 512), "\0");

        // Two zero blocks mark end of archive.
        return $header . $padded . str_repeat("\0", 1024);
    }
}
