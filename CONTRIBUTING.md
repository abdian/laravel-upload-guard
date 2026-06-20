# Contributing to Laravel Safeguard

Thank you for considering contributing to Laravel Safeguard! This document outlines the process for contributing to this project.

---

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code.

---

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Laravel version** and PHP version
- **Code samples** if applicable

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Clear use case** for the feature
- **Why this would be useful** to most users
- **Possible implementation** ideas

### Security Vulnerabilities

**DO NOT** open issues for security vulnerabilities. Please follow [SECURITY.md](SECURITY.md) — email esanjdev@gmail.com or open a private GitHub Security Advisory.

---

## Development Setup

### Prerequisites

- PHP 8.1+
- Composer
- Laravel 10.x through 13.x

### Setup

```bash
# Clone repository
git clone https://github.com/abdian/laravel-upload-guard.git
cd laravel-upload-guard

# Install dependencies
composer install

# Run tests
composer test
```

---

## Pull Request Process

### Before Submitting

1. **Update documentation** if needed
2. **Add tests** for new features
3. **Follow coding standards** (PSR-12)
4. **Run tests** and ensure they pass
5. **Update CHANGELOG.md** with your changes

### Coding Standards

This project follows PSR-12 coding standards:

```bash
# Check code style
composer phpcs

# Fix code style
composer phpcbf
```

### Commit Messages

Use clear and meaningful commit messages:

- `feat: Add new validation rule for...`
- `fix: Resolve issue with MIME detection`
- `docs: Update installation guide`
- `test: Add tests for PHP scanner`
- `refactor: Improve performance of...`

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Code follows PSR-12
- [ ] All tests pass
```

---

## Adding New File Type Support

To add support for a new file type:

1. **Add magic bytes** to `MimeTypeDetector.php`:

```php
protected array $magicBytes = [
    // Add your signature
    '6674797068656963' => 'image/heic',
];
```

2. **Add tests** in `tests/MimeTypeDetectorTest.php`

3. **Update documentation** in `docs/customization.md`

---

## Adding New Security Checks

To add a new security scanner:

1. **Create scanner class** in `src/` (e.g., `DocxScanner.php`)
2. **Create validation rule** in `src/Rules/` (e.g., `SafeguardDocx.php`)
3. **Register rule** in `SafeguardServiceProvider.php`
4. **Add tests**
5. **Update documentation**

---

## Running Tests

```bash
# Run all tests
composer test

# Run specific test
./vendor/bin/phpunit --filter MimeTypeDetectorTest

# Run with coverage
composer test-coverage
```

---

## Documentation

Documentation is in the `docs/` folder. When adding features:

1. Update relevant documentation files
2. Add examples if applicable
3. Update README.md links if adding new docs

---

## Release Process

(For maintainers only)

1. Update version in `composer.json`
2. Update `CHANGELOG.md`
3. Create git tag: `git tag v1.x.x`
4. Push: `git push origin v1.x.x`
5. Create GitHub release
6. Publish to Packagist (automatic)

---

## Questions?

Feel free to open a discussion on GitHub for questions about contributing.

Thank you for contributing! 🎉
