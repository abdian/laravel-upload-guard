<?php

namespace Abdian\UploadGuard\Tests\Feature;

use Abdian\UploadGuard\Rules\Safeguard;
use Abdian\UploadGuard\Rules\SafeguardArchive;
use Abdian\UploadGuard\Tests\Support\Fixtures;
use Abdian\UploadGuard\Tests\TestCase;
use Illuminate\Support\Facades\Validator;
use PHPUnit\Framework\Attributes\DataProvider;

class OrchestrationTest extends TestCase
{
    private function validate($uploaded, $rule = 'required|safeguard'): \Illuminate\Validation\Validator
    {
        return Validator::make(['file' => $uploaded], ['file' => $rule]);
    }

    public function test_benign_image_passes_string_rule(): void
    {
        $v = $this->validate($this->uploadedFile(Fixtures::png(), 'a.png'));
        $this->assertTrue($v->passes(), implode(',', $v->errors()->all()));
    }

    public function test_polyglot_php_in_jpeg_is_rejected(): void
    {
        $v = $this->validate($this->uploadedFile(Fixtures::phpInJpeg(), 'a.jpg'));
        $this->assertTrue($v->fails());
    }

    public function test_default_rule_blocks_zip_traversal_without_fluent_call(): void
    {
        // Archive scanning is ON by default; no scanArchives() needed.
        $v = $this->validate($this->uploadedFile(Fixtures::zipTraversalBenign(), 'a.zip'));
        $this->assertTrue($v->fails());
    }

    public function test_default_rule_blocks_macro_document(): void
    {
        // Office scanning is ON by default; no blockMacros() needed.
        $v = $this->validate($this->uploadedFile(Fixtures::docxWithMacro(), 'a.docx'));
        $this->assertTrue($v->fails());
    }

    public function test_dangerous_jar_is_blocked(): void
    {
        $v = $this->validate($this->uploadedFile(Fixtures::jar(), 'a.jar'));
        $this->assertTrue($v->fails());
    }

    public function test_unknown_type_with_php_opener_fails_closed(): void
    {
        $v = $this->validate($this->uploadedFile(Fixtures::phpInOctetStream(), 'a.bin'));
        $this->assertTrue($v->fails());
    }

    public function test_uppercase_svg_extension_is_routed_and_sanitized(): void
    {
        $file = $this->uploadedFile(Fixtures::svgWithScript(), 'EVIL.SVG');
        $rule = new Safeguard();
        $failed = false;
        $rule->validate('file', $file, function () use (&$failed) {
            $failed = true;
        });
        // sanitize mode: passes but the stored bytes are cleaned of the script.
        $this->assertFalse($failed);
        $this->assertStringNotContainsString('<script', (string) file_get_contents($file->getRealPath()));
    }

    public function test_works_without_http_request_context(): void
    {
        // Testbench runs without a bound request; this must not throw.
        $v = $this->validate($this->uploadedFile(Fixtures::png(), 'a.png'));
        $this->assertTrue($v->passes());
    }

    public function test_rate_limit_rejects_oversize_file(): void
    {
        config([
            'safeguard.rate_limiting.enabled' => true,
            'safeguard.rate_limiting.max_file_size' => 10,
        ]);
        $v = $this->validate($this->uploadedFile(str_repeat('A', 1024), 'big.txt'));
        $this->assertTrue($v->fails());
    }

    public function test_strict_extension_mismatch_rejected(): void
    {
        // A real PNG uploaded as .jpg should be rejected by strict matching.
        $v = $this->validate($this->uploadedFile(Fixtures::png(), 'image.jpg'));
        $this->assertTrue($v->fails());
    }

    public function test_mimes_integration_allows_declared_type(): void
    {
        $v = $this->validate($this->uploadedFile(Fixtures::png(), 'a.png'), 'required|safeguard|mimes:png,jpg');
        $this->assertTrue($v->passes(), implode(',', $v->errors()->all()));
    }

    #[DataProvider('legitimateTextProvider')]
    public function test_legitimate_text_files_are_not_false_rejected(string $bytes, string $name): void
    {
        $v = $this->validate($this->uploadedFile($bytes, $name));
        $this->assertTrue($v->passes(), "{$name} should pass: " . implode(',', $v->errors()->all()));
    }

    public static function legitimateTextProvider(): array
    {
        return [
            'javascript' => [Fixtures::javascriptSource(), 'app.js'],
            'json' => ['{"a":1,"b":[2,3]}', 'data.json'],
            'css' => ["body { color: #fff; }\n.x { display: none; }", 'style.css'],
            'markdown' => [Fixtures::markdown(), 'README.md'],
            'python' => [Fixtures::pythonSource(), 'script.py'],
            'csv' => [Fixtures::csv(), 'data.csv'],
            'plain' => ["just some notes\nno code here", 'notes.txt'],
        ];
    }

    public function test_strict_extension_matching_can_be_disabled(): void
    {
        // A real PNG uploaded as .jpg is rejected by default (strict). The fluent
        // strictExtensionMatching(false) must actually disable it (tri-state),
        // not be overridden by the config default.
        $file = $this->uploadedFile(Fixtures::png(), 'image.jpg');
        $failed = false;
        (new Safeguard())->strictExtensionMatching(false)->validate('file', $file, function () use (&$failed) {
            $failed = true;
        });
        $this->assertFalse($failed, 'strictExtensionMatching(false) must turn off extension/content matching');
    }

    public function test_archive_rule_does_not_leak_overrides_into_global_config(): void
    {
        $before = config('safeguard.archive_scanning.exclude_extensions');
        $file = $this->uploadedFile(Fixtures::zipTraversalBenign(), 'a.zip');
        (new SafeguardArchive())->allow(['sh'])->validate('file', $file, function () {});
        $this->assertSame($before, config('safeguard.archive_scanning.exclude_extensions'), 'per-instance allow() must be restored, not leaked to global config');
    }
}
