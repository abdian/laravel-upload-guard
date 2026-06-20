# Tasks: Critical Security Enhancements

## 1. XXE Protection in SVG/XML Parsing

- [x] 1.1 Add XXE protection to `SvgScanner::scan()` method
- [x] 1.2 Create PHP 8.0+ compatible implementation using LIBXML_NOENT
- [x] 1.3 Add DTD/entity detection in raw content before parsing
- [ ] 1.4 Write unit tests for XXE attack vectors
- [ ] 1.5 Update documentation with XXE protection details

## 2. Symlink/Hardlink Validation

- [x] 2.1 Create `ValidatesFileAccess` trait in `src/Concerns/`
- [x] 2.2 Implement `validateFileAccess()` method with symlink check
- [x] 2.3 Implement path validation (ensure file in allowed directories)
- [x] 2.4 Apply trait to all existing scanner classes:
  - [x] 2.4.1 `SvgScanner`
  - [x] 2.4.2 `ImageScanner`
  - [x] 2.4.3 `PdfScanner`
  - [x] 2.4.4 `PhpCodeScanner`
- [x] 2.5 Add configuration option `security.allowed_upload_paths`
- [ ] 2.6 Write unit tests for symlink attack scenarios

## 3. Archive Content Scanning

- [x] 3.1 Create `ArchiveScanner` class in `src/`
- [x] 3.2 Implement ZIP support using native ZipArchive
- [x] 3.3 Implement dangerous extension detection
- [x] 3.4 Implement path traversal detection (`../` patterns)
- [x] 3.5 Implement compression ratio check (zip bomb detection)
- [x] 3.6 Implement nested archive scanning with depth limit
- [x] 3.7 Implement file count limit check
- [x] 3.8 Implement uncompressed size limit check
- [x] 3.9 Add optional TAR/GZIP support via PharData
- [x] 3.10 Add optional RAR support (graceful if extension missing)
- [x] 3.11 Create `SafeguardArchive` validation rule
- [x] 3.12 Add `archive_scanning` config section
- [x] 3.13 Register rule in `SafeguardServiceProvider`
- [ ] 3.14 Write comprehensive unit tests

## 4. Office Document Macro Detection

- [x] 4.1 Create `OfficeScanner` class in `src/`
- [x] 4.2 Implement Office Open XML detection (check for ZIP structure)
- [x] 4.3 Implement `vbaProject.bin` file detection
- [x] 4.4 Implement `[Content_Types].xml` parsing for macro indicators
- [x] 4.5 Detect macro-enabled extensions disguised as regular extensions
- [x] 4.6 Implement ActiveX control detection (optional)
- [x] 4.7 Create `SafeguardOffice` validation rule
- [x] 4.8 Add `office_scanning` config section
- [x] 4.9 Register rule in `SafeguardServiceProvider`
- [ ] 4.10 Write unit tests with sample macro-enabled documents

## 5. Integration and Testing

- [x] 5.1 Update `Safeguard` main rule to include new scanners
- [x] 5.2 Add new scanners to fluent API:
  - [x] 5.2.1 `->scanArchives()` method
  - [x] 5.2.2 `->blockMacros()` method
- [x] 5.3 Update SecurityLogger with new event types:
  - [x] 5.3.1 `XXE_DETECTED`
  - [x] 5.3.2 `ARCHIVE_THREAT`
  - [x] 5.3.3 `MACRO_DETECTED`
  - [x] 5.3.4 `SYMLINK_DETECTED`
  - [x] 5.3.5 `ZIPBOMB_DETECTED`
- [ ] 5.4 Create integration tests
- [ ] 5.5 Create security-focused test suite with attack samples
- [x] 5.6 Update README with new features
- [x] 5.7 Update VitePress documentation

## 6. Configuration

- [x] 6.1 Add `archive_scanning` section to config:
  ```php
  'archive_scanning' => [
      'enabled' => false,
      'max_compression_ratio' => 100,
      'max_uncompressed_size' => 500 * 1024 * 1024,
      'max_files_count' => 10000,
      'max_nesting_depth' => 3,
      'blocked_extensions' => ['php', 'phar', 'exe', 'bat', 'sh', 'cmd', 'ps1'],
  ]
  ```
- [x] 6.2 Add `office_scanning` section to config:
  ```php
  'office_scanning' => [
      'enabled' => true,
      'block_macros' => true,
      'block_activex' => true,
      'allowed_macro_extensions' => ['docm', 'xlsm', 'pptm'],
  ]
  ```
- [x] 6.3 Add `security` section to config:
  ```php
  'security' => [
      'check_symlinks' => true,
      'allowed_upload_paths' => null, // null = auto-detect
  ]
  ```

## Dependencies

```
Task 2 (Symlink) blocks Task 3 and 4 (new scanners should use trait)
Task 3.5 (Zip bomb) is part of Task 3 (Archive) but can be developed in parallel
Task 5 depends on Tasks 1-4 completion
Task 6 can be done in parallel with Tasks 1-4
```

## Verification Checklist

- [x] All existing unit tests pass
- [ ] PHPStan level 8 passes (if configured)
- [x] No breaking changes to existing API
- [x] Documentation updated
- [x] Config published correctly
- [ ] Security tests cover attack vectors from fixes.md

## Implementation Summary

### Files Created
- `src/Concerns/ValidatesFileAccess.php` - Symlink validation trait
- `src/ArchiveScanner.php` - Archive content scanning
- `src/OfficeScanner.php` - Office macro detection
- `src/Rules/SafeguardArchive.php` - Archive validation rule
- `src/Rules/SafeguardOffice.php` - Office validation rule

### Files Modified
- `src/SvgScanner.php` - Added XXE protection + symlink validation
- `src/ImageScanner.php` - Added symlink validation
- `src/PdfScanner.php` - Added symlink validation
- `src/PhpCodeScanner.php` - Added symlink validation
- `src/SecurityLogger.php` - Added new event types
- `src/SafeguardServiceProvider.php` - Registered new rules
- `src/Rules/Safeguard.php` - Added fluent methods for new features
- `src/config/safeguard.php` - Added new configuration sections
