# Change: Add Critical Security Enhancements

## Why

The current Laravel Safeguard package has critical security gaps that allow attackers to bypass protection mechanisms:

1. **XXE Attacks**: SVG/XML parsing doesn't disable external entity loading, enabling file disclosure and DoS attacks
2. **Malicious Archives**: Archive files (ZIP/RAR/7Z) pass validation but may contain malware, PHP shells, or exploit path traversal
3. **Office Macros**: DOCX/XLSX/PPTX files can contain VBA macros used for malware distribution
4. **TOCTOU Attacks**: Symlinks to system files can bypass scanning via time-of-check-time-of-use vulnerabilities
5. **Resource Exhaustion**: Zip bombs can consume all disk space and memory during extraction

## What Changes

### New Classes
- `ArchiveScanner` - Scans archive contents for dangerous files, path traversal, and zip bombs
- `OfficeScanner` - Detects VBA macros in Office Open XML documents

### Modified Classes
- **BREAKING**: `SvgScanner` - Adds XXE protection before XML parsing
- All scanner classes - Add symlink/hardlink validation before scanning

### New Validation Rules
- `safeguard_archive` - Archive content scanning rule
- `safeguard_office` - Office macro detection rule

### Configuration Changes
- New `archive_scanning` section with extraction limits
- New `office_scanning` section with macro blocking options
- New `security.symlink_check` option for TOCTOU protection

## Impact

- **Affected specs**: None (first spec creation)
- **Affected code**:
  - `src/SvgScanner.php` - XXE protection
  - `src/ArchiveScanner.php` (new)
  - `src/OfficeScanner.php` (new)
  - `src/Rules/SafeguardArchive.php` (new)
  - `src/Rules/SafeguardOffice.php` (new)
  - `src/config/safeguard.php` - New configuration sections
  - `src/SafeguardServiceProvider.php` - Register new rules
  - All scanner classes - Symlink validation trait/method

## Risk Assessment

| Enhancement | Severity | Effort | Risk |
|-------------|----------|--------|------|
| XXE Protection | Critical | Low | Low |
| Archive Scanning | Critical | High | Medium |
| Office Macro Detection | Critical | Medium | Low |
| Symlink Validation | High | Low | Low |
| Zip Bomb Detection | High | Medium | Low |

## Compatibility

- PHP 8.1+ required (uses match expressions, typed properties)
- ZipArchive extension required for archive scanning
- No breaking changes to existing public API
- New features are opt-in via configuration
