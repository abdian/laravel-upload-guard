# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x: (dev-only)     |

## Reporting a Vulnerability

If you discover a security vulnerability in Laravel Safeguard, please report it
**privately** so it can be fixed before public disclosure.

- **Preferred:** open a private advisory via
  [GitHub Security Advisories](https://github.com/abdian/laravel-upload-guard/security/advisories/new).
- **Email:** esanjdev@gmail.com

Please include:

- a description of the vulnerability and its impact;
- a minimal proof-of-concept or steps to reproduce;
- the package version and PHP/Laravel versions.

You will receive an acknowledgement within **72 hours**. Once the issue is
confirmed, a fix and coordinated disclosure timeline will be agreed with you.
Please do not open a public issue for security reports.

## Scope and Guarantees

Laravel Safeguard is a **synchronous validation library**, not an antivirus. It
is designed to **fail closed**: when it cannot be sure a file is safe, it blocks
the upload. It defends against the documented threat classes (polyglot web
shells, malicious PDFs/SVGs, zip bombs, Office macros, MIME spoofing,
decompression-bomb images) but does **not** perform AV signature scanning,
sandboxed detonation, or ML classification.

Validating an uploaded temp file does not by itself close the temp→storage
time-of-check/time-of-use (TOCTOU) window. Use the provided
`validateDestinationPath()` helper immediately before moving a validated upload
to its final location, and prefer re-encoding images where feasible.
