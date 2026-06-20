# Design: Critical Security Enhancements

## Context

Laravel Safeguard validates uploaded files for security threats. The current implementation has gaps that sophisticated attackers can exploit. This design addresses five critical security vulnerabilities identified in the security audit.

### Stakeholders
- Package maintainers
- Laravel developers using the package
- Security teams auditing applications

### Constraints
- Must maintain backward compatibility
- Cannot add heavy dependencies (e.g., no ClamAV requirement)
- Must work with PHP 8.1+ and Laravel 10/11/12
- Performance impact must be minimal for normal files

## Goals / Non-Goals

### Goals
- Prevent XXE attacks through SVG/XML files
- Detect malicious content in archive files
- Detect VBA macros in Office documents
- Prevent TOCTOU attacks via symlinks
- Detect and block zip bomb attacks

### Non-Goals
- Full antivirus scanning (out of scope)
- Deep learning-based malware detection
- Real-time file monitoring
- Network-based threat intelligence

## Decisions

### Decision 1: XXE Protection Implementation

**What**: Use `libxml_disable_entity_loader()` and `libxml_use_internal_errors()` before any XML parsing in SvgScanner.

**Why**: This is the standard PHP approach to prevent XXE attacks. It's lightweight and doesn't require external dependencies.

**Alternatives considered**:
- DOMDocument with LIBXML_NOENT flag - More complex, same result
- Regex-only scanning - Insufficient, can be bypassed

**Code pattern**:
```php
// Store previous state
$disableEntities = libxml_disable_entity_loader(true);
$useErrors = libxml_use_internal_errors(true);

try {
    // Parse XML safely
} finally {
    // Restore previous state
    libxml_disable_entity_loader($disableEntities);
    libxml_use_internal_errors($useErrors);
}
```

Note: `libxml_disable_entity_loader()` is deprecated in PHP 8.0+ but still functional. For PHP 8.0+, use `LIBXML_NOENT` flag instead.

### Decision 2: Archive Scanner Architecture

**What**: Create `ArchiveScanner` class that handles ZIP files natively and delegates RAR/7Z to optional extensions.

**Why**: ZipArchive is built into PHP. RAR/7Z support should be optional to avoid hard dependencies.

**Architecture**:
```
ArchiveScanner
├── scan(file) - Entry point
├── openArchive(file) - Factory for format-specific handling
├── listContents(archive) - Get file listing without extraction
├── checkForDangerousFiles(listing) - Extension-based checks
├── checkForPathTraversal(listing) - Detect ../ attacks
├── checkCompressionRatio(archive) - Zip bomb detection
└── validateNestedArchives(archive, depth) - Recursive check
```

**Supported formats**:
- ZIP (native via ZipArchive)
- RAR (optional via rar extension)
- 7Z (optional via p7zip command)
- TAR/GZIP (native via PharData)

### Decision 3: Office Macro Detection Strategy

**What**: Treat Office Open XML files as ZIP archives and check for `vbaProject.bin` and macro content types.

**Why**: Office Open XML (DOCX, XLSX, PPTX) are ZIP files containing XML. Macros are stored in predictable locations.

**Detection logic**:
1. Open file as ZipArchive
2. Check for `vbaProject.bin` in any directory
3. Parse `[Content_Types].xml` for macro indicators:
   - `application/vnd.ms-office.vbaProject`
   - `application/vnd.ms-word.document.macroEnabled`
   - `application/vnd.ms-excel.sheet.macroEnabled`
   - `application/vnd.ms-powerpoint.presentation.macroEnabled`

**Edge cases**:
- `.docm`/`.xlsm`/`.pptm` disguised as `.docx`/`.xlsx`/`.pptx`
- ActiveX controls embedded in documents
- External data connections

### Decision 4: Symlink Validation Approach

**What**: Add `validateFileAccess()` method as a trait that all scanners must call before reading files.

**Why**: A trait allows reuse across all scanner classes without changing inheritance hierarchy.

**Validation checks**:
1. `is_link($path)` - Reject symlinks
2. `realpath($path)` - Resolve actual path
3. Path prefix validation - Ensure file is in expected directory

**Implementation**:
```php
trait ValidatesFileAccess
{
    protected function validateFileAccess(string $path): bool
    {
        // Reject symlinks
        if (is_link($path)) {
            return false;
        }

        // Ensure real path exists
        $realPath = realpath($path);
        if ($realPath === false) {
            return false;
        }

        // Verify file is in allowed directory
        $allowedDirs = [
            sys_get_temp_dir(),
            storage_path('app'),
        ];

        foreach ($allowedDirs as $dir) {
            $realDir = realpath($dir);
            if ($realDir && str_starts_with($realPath, $realDir)) {
                return true;
            }
        }

        return false;
    }
}
```

### Decision 5: Zip Bomb Detection Algorithm

**What**: Calculate compression ratio and reject files exceeding configurable threshold.

**Why**: Zip bombs exploit high compression ratios (e.g., 1MB compressed to 1GB uncompressed).

**Algorithm**:
```php
function isZipBomb(string $path): bool
{
    $zip = new ZipArchive();
    $zip->open($path);

    $compressedSize = filesize($path);
    $uncompressedSize = 0;

    for ($i = 0; $i < $zip->numFiles; $i++) {
        $stat = $zip->statIndex($i);
        $uncompressedSize += $stat['size'];

        // Early exit if already exceeds limit
        if ($uncompressedSize > $this->maxUncompressedSize) {
            return true;
        }
    }

    // Check ratio (default: 100:1 is suspicious)
    $ratio = $uncompressedSize / max($compressedSize, 1);
    return $ratio > $this->maxCompressionRatio;
}
```

**Configurable limits**:
- `max_compression_ratio`: 100 (default)
- `max_uncompressed_size`: 500MB (default)
- `max_files_count`: 10000 (default)
- `max_nesting_depth`: 3 (default)

## Risks / Trade-offs

| Risk | Impact | Mitigation |
|------|--------|------------|
| Performance overhead for large archives | Medium | Add file size limits, early exit on threshold breach |
| False positives on legitimate high-compression | Low | Make ratio configurable, document exceptions |
| RAR/7Z support requires extensions | Low | Graceful degradation, clear error messages |
| `libxml_disable_entity_loader` deprecated | Low | Use LIBXML_NOENT flag for PHP 8.0+ |
| Nested archive depth limits | Low | Configurable depth, default to 3 levels |

## Migration Plan

### Phase 1: Non-Breaking Changes
1. Add XXE protection to SvgScanner (internal change)
2. Add symlink validation trait (internal change)
3. Add new ArchiveScanner class
4. Add new OfficeScanner class

### Phase 2: Configuration
1. Add new config sections with sensible defaults
2. New features disabled by default for existing users
3. Document migration path

### Phase 3: Rules Integration
1. Register new validation rules
2. Update documentation
3. Add to test suite

### Rollback
All changes are additive. Rollback by:
1. Removing new scanner classes
2. Reverting SvgScanner XXE changes
3. Removing config sections

## Open Questions

1. **Should archive scanning be enabled by default?**
   - Recommendation: No, opt-in for backward compatibility

2. **How to handle password-protected archives?**
   - Recommendation: Fail closed (reject if can't scan)

3. **Should we scan archive contents recursively by default?**
   - Recommendation: Yes, with configurable depth limit (default: 3)

4. **What about other archive formats (CAB, ISO, DMG)?**
   - Recommendation: Phase 2 enhancement, not in initial scope
