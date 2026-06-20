---
layout: home

hero:
  name: Laravel Safeguard
  text: Fail-Closed File Upload Validation
  tagline: Block polyglot web shells, malicious PDFs/SVGs, zip bombs, Office macros, and spoofed MIME types — with structural parsing and content sanitization.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/
    - theme: alt
      text: View on GitHub
      link: https://github.com/abdian/laravel-upload-guard

features:
  - icon: 🔒
    title: Fail-Closed by Default
    details: When the package cannot be sure a file is safe, it blocks. Unknown types, unparsable containers, and scanner errors all reject.

  - icon: 🐚
    title: Always-On Code Scanning
    details: Every upload is scanned for PHP/script openers regardless of type — polyglot web shells appended after a magic header are caught.

  - icon: 🔍
    title: Structural MIME Detection
    details: Classifies by byte structure with subtype disambiguation (real .xls → Excel, JAR/APK), returning untrusted for unknown content.

  - icon: 🧼
    title: SVG Sanitization & PDF Decoding
    details: SVGs are sanitized (cleaned output stored); PDFs are inflated (Flate/ObjStm, #xx names) before scanning /OpenAction & /JS.

  - icon: 📦
    title: Real Zip-Bomb & Macro Detection
    details: Archives stream against a hard cap on actual bytes; OLE + OOXML macros are resolved via relationships, failing closed.

  - icon: ⚙️
    title: Laravel 10/11/12/13 · PHP 8.1–8.5
    details: Fluent API, config-driven defaults (archive + Office scanning on), DoS rate guard, and opt-in quarantine.
---

> Laravel Safeguard is a synchronous validation library, not an antivirus. See the
> [README](https://github.com/abdian/laravel-upload-guard#readme) and
> [UPGRADE guide](https://github.com/abdian/laravel-upload-guard/blob/main/UPGRADE.md)
> for exact behavior, guarantees, and limitations.
