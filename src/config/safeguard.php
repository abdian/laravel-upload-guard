<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Global Scan Bounds (DoS / performance budget)
    |--------------------------------------------------------------------------
    |
    | The package reads each upload once and bounds the work it performs. Files
    | larger than `max_scan_size` are handled per `over_cap_policy`:
    |   - 'reject'      : the upload is rejected (fail-closed, default)
    |   - 'header_only' : only the header (type detection) runs; deep content
    |                     scanning is skipped. Use only when you accept the risk.
    |
    | `header_window` is the number of leading bytes read for content-based type
    | detection (must be >= 512).
    |
    */

    'max_scan_size' => env('SAFEGUARD_MAX_SCAN_SIZE', 25 * 1024 * 1024), // 25 MB
    'over_cap_policy' => env('SAFEGUARD_OVER_CAP_POLICY', 'reject'),
    'header_window' => env('SAFEGUARD_HEADER_WINDOW', 512),

    /*
    |--------------------------------------------------------------------------
    | MIME Type Validation
    |--------------------------------------------------------------------------
    */

    'mime_validation' => [
        // Fail if the file extension does not match the detected (real) content type.
        'strict_check' => env('SAFEGUARD_MIME_STRICT', true),

        // Automatically block dangerous file types (executables, scripts, JAR/APK).
        'block_dangerous' => env('SAFEGUARD_MIME_BLOCK_DANGEROUS', true),

        // Reject files whose real content type cannot be determined when no
        // allowlist constrains them. Off by default (the always-on code scanner
        // still inspects undetectable files); enable for strict deployments.
        'block_undetectable' => env('SAFEGUARD_MIME_BLOCK_UNDETECTABLE', false),

        // Extensions blocked for TOP-LEVEL uploads — active/abusable formats that
        // frequently sniff as plain text (Windows shell/shortcut, Office data
        // connections, scripts). Enforced only when no allowedMimes() is set.
        'blocked_extensions' => [
            'hta', 'scf', 'lnk', 'url', 'desktop', 'reg', 'wsf', 'wsh',
            'iqy', 'slk', 'vbs', 'vbe', 'ps1', 'jse', 'jnlp',
        ],

        // Custom magic-byte signatures. Format: 'hexsignature' => 'mime/type'.
        // Checked before the built-in table; keys must be lowercase hex.
        'custom_signatures' => [
            // 'cafebabe' => 'application/java-vm',
        ],

        // MIME types treated as dangerous and rejected when `block_dangerous` is on.
        'dangerous_types' => [
            // Executables / native binaries
            'application/x-msdownload',
            'application/x-msdos-program',
            'application/x-executable',
            'application/x-elf',
            'application/x-sharedlib',
            'application/x-mach-binary',
            'application/x-dosexec',
            'application/vnd.microsoft.portable-executable',

            // Server-side scripts
            'application/x-php',
            'text/x-php',
            'application/x-httpd-php',
            'application/x-httpd-php-source',
            'text/x-shellscript',
            'application/x-sh',
            'application/x-csh',
            'application/x-perl',
            'text/x-perl',
            'application/x-python',
            'text/x-python',
            'application/x-ruby',
            'text/x-ruby',
            'text/x-jsp',

            // Active web content (stored XSS / HTML smuggling). Blocked by
            // default; allowlist via mimes/allowedMimes if you truly accept HTML.
            'text/html',
            'application/xhtml+xml',
            'application/hta',

            // Java / Android archives (executable bytecode containers)
            'application/java-archive',
            'application/java-vm',
            'application/vnd.android.package-archive',

            // Installers / batch
            'application/x-bat',
            'application/x-msi',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | PHP / Script Code Scanning  (runs on EVERY upload, always-on)
    |--------------------------------------------------------------------------
    |
    | The byte scanner for PHP/script openers cannot be disabled per file type:
    | a valid image/PDF/zip header never exempts a file from code scanning.
    | `enabled` only governs the deeper function/keyword analysis layer.
    |
    */

    'php_scanning' => [
        'enabled' => env('SAFEGUARD_PHP_SCAN', true),

        // Scan mode for the function/keyword layer:
        //   'default' : built-in dangerous-function list (+ custom additions)
        //   'strict'  : superset of 'default' plus extra high-risk functions
        //   'custom'  : only the functions listed in 'scan_functions'
        'mode' => env('SAFEGUARD_PHP_MODE', 'default'),

        // When true, the function layer tokenizes PHP regions with token_get_all()
        // (bounded by max_scan_size) to catch variable functions / dynamic dispatch
        // instead of relying on substring matching.
        'deep_analysis' => env('SAFEGUARD_PHP_DEEP', true),

        // Functions scanned in 'custom' mode (an empty list raises a config warning).
        'scan_functions' => [],

        // Extra dangerous functions added to the built-in list.
        'custom_dangerous_functions' => [],

        // Functions removed from the scan set even if built-in.
        'exclude_functions' => [],

        // Extra suspicious regex patterns. Each is validated at load time; an
        // invalid pattern is dropped with a config warning (no @-suppression).
        'custom_patterns' => [],

        // Patterns removed from the built-in set.
        'exclude_patterns' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | SVG Sanitization
    |--------------------------------------------------------------------------
    |
    | SVG uploads are run through an allowlist sanitizer (enshrined/svg-sanitize).
    | The sanitized bytes are written back to the file so the stored SVG is clean.
    | Set `mode` to 'reject' to refuse any SVG that required changes instead of
    | rewriting it.
    |
    | NOTE: the legacy `custom_dangerous_tags` / `exclude_tags` blocklist keys are
    | removed — sanitization is allowlist-based, not blocklist-based.
    |
    */

    'svg_scanning' => [
        'enabled' => env('SAFEGUARD_SVG_SCAN', true),

        // 'sanitize' : clean the file and store the sanitized output (default)
        // 'reject'   : reject any SVG that is not already clean
        'mode' => env('SAFEGUARD_SVG_MODE', 'sanitize'),

        // Remove references to remote resources (use/image href to http(s)/file).
        'remove_remote_references' => true,

        // Optional allowlist overrides for the sanitizer. Leave empty to use the
        // library's vetted defaults.
        'allowed_tags' => [],       // e.g. ['svg', 'path', 'g', 'rect', 'circle']
        'allowed_attributes' => [], // e.g. ['d', 'fill', 'viewBox', 'width', 'height']
    ],

    /*
    |--------------------------------------------------------------------------
    | Image Security Scanning
    |--------------------------------------------------------------------------
    */

    'image_scanning' => [
        'enabled' => env('SAFEGUARD_IMAGE_SCAN', true),

        // Decompression-bomb guard, enforced from the header BEFORE any decode.
        // Reject images whose declared pixel count or byte size exceeds these caps.
        'max_pixels' => env('SAFEGUARD_IMAGE_MAX_PIXELS', 64_000_000), // ~64 MP
        'max_bytes' => env('SAFEGUARD_IMAGE_MAX_BYTES', 20 * 1024 * 1024),

        // GPS / EXIF handling.
        'check_gps' => env('SAFEGUARD_IMAGE_CHECK_GPS', true),
        'block_gps' => env('SAFEGUARD_IMAGE_BLOCK_GPS', false),

        // Re-encode uploads through GD/Imagick to strip appended/segment payloads.
        // Recommended but opt-in because it rewrites bytes. Requires ext-gd or
        // ext-imagick; if neither is present the request fails loudly.
        'reencode' => env('SAFEGUARD_IMAGE_REENCODE', false),
        'reencode_quality' => env('SAFEGUARD_IMAGE_REENCODE_QUALITY', 85),
    ],

    /*
    |--------------------------------------------------------------------------
    | PDF Security Scanning
    |--------------------------------------------------------------------------
    |
    | PDFs are decoded (Flate/LZW/ASCII85/ASCIIHex inflation, /ObjStm parsing,
    | #xx name decoding) before matching. Auto-run triggers /OpenAction and /AA
    | are always covered.
    |
    */

    'pdf_scanning' => [
        'enabled' => env('SAFEGUARD_PDF_SCAN', true),

        // Extra dangerous actions to flag (PDF name objects, e.g. '/SubmitForm').
        'custom_dangerous_actions' => [],

        // Actions removed from the built-in set.
        'exclude_actions' => [],

        // How to handle encrypted PDFs that cannot be decrypted with the empty
        // password: 'reject' (fail-closed, default) or 'allow' (not recommended).
        'encrypted_policy' => env('SAFEGUARD_PDF_ENCRYPTED', 'reject'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Archive Scanning  (enabled by default)
    |--------------------------------------------------------------------------
    |
    | Zip-bomb detection streams each entry through a bounded reader and counts
    | ACTUAL decompressed bytes against `max_decompressed_size`. Central-directory
    | sizes are only used to flag declared-vs-actual mismatches.
    |
    | NOTE: the legacy `max_compression_ratio` key is removed — it is superseded
    | by the actual-decompressed-bytes cap below.
    |
    */

    'archive_scanning' => [
        'enabled' => env('SAFEGUARD_ARCHIVE_SCAN', true),

        // Hard cap on total ACTUAL decompressed bytes; streaming aborts past it.
        'max_decompressed_size' => env('SAFEGUARD_ARCHIVE_MAX_BYTES', 500 * 1024 * 1024),

        // Maximum number of entries allowed in an archive.
        'max_files_count' => env('SAFEGUARD_ARCHIVE_MAX_FILES', 10000),

        // Maximum recursion depth for archives nested inside archives.
        'max_nesting_depth' => env('SAFEGUARD_ARCHIVE_MAX_DEPTH', 3),

        // Dangerous extensions blocked on ANY dotted segment of an entry name.
        'blocked_extensions' => [
            'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar',
            'shtml', 'inc',
            'exe', 'dll', 'com', 'scr', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse',
            'sh', 'bash', 'cgi', 'pl', 'py', 'rb',
            'jar', 'jsp', 'jspx', 'war', 'asp', 'aspx', 'ashx',
            'htaccess', 'htpasswd',
            // Windows shortcut / shell / config (credential theft & RCE on extract)
            'hta', 'scf', 'lnk', 'url', 'desktop', 'reg', 'wsf', 'wsh',
            // Office data-connection / legacy formats that auto-fetch or run DDE/XLM
            'slk', 'iqy', 'mht', 'mhtml',
        ],

        // Entries whose dangerous extension is intentionally allowed.
        'exclude_extensions' => [],

        // Filenames (case-insensitive, any segment) that are always blocked.
        'blocked_filenames' => [
            '.htaccess', '.htpasswd', 'web.config',
            '.user.ini', 'desktop.ini', 'autorun.inf',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Office Document Scanning  (enabled by default)
    |--------------------------------------------------------------------------
    |
    | Covers both OOXML (zip) and legacy OLE/CFB (.doc/.xls/.ppt). Parts are
    | located case-insensitively and resolved via OPC relationships, not by
    | hard-coded filenames. Fails closed when a container cannot be parsed and
    | macro blocking is on.
    |
    */

    'office_scanning' => [
        'enabled' => env('SAFEGUARD_OFFICE_SCAN', true),
        'block_macros' => env('SAFEGUARD_BLOCK_MACROS', true),
        'block_activex' => env('SAFEGUARD_BLOCK_ACTIVEX', true),

        // Extensions allowed to legitimately carry macros (informational; macros
        // are still blocked when block_macros is on unless allowMacros() is used).
        'allowed_macro_extensions' => ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm'],
    ],

    /*
    |--------------------------------------------------------------------------
    | File Access / Path Confinement
    |--------------------------------------------------------------------------
    */

    'security' => [
        // Reject symbolic links (TOCTOU hardening).
        'check_symlinks' => env('SAFEGUARD_CHECK_SYMLINKS', true),

        // Allowed directories. null = auto-detect (system temp + upload_tmp_dir +
        // storage/app). An explicitly-empty array fails closed (rejects all).
        'allowed_upload_paths' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Upload Rate / Size Limiting (DoS guard)
    |--------------------------------------------------------------------------
    |
    | Limits how much scanning work an attacker can force. Per-minute limits are
    | request-IP keyed and are skipped (without error) outside an HTTP context;
    | the size limit is always enforced.
    |
    */

    'rate_limiting' => [
        'enabled' => env('SAFEGUARD_RATE_LIMIT', false),

        // Absolute per-file ceiling (independent of max_scan_size). 0 = no limit.
        'max_file_size' => env('SAFEGUARD_RL_MAX_FILE_SIZE', 50 * 1024 * 1024),

        // Per-IP, per-minute caps. 0 = no limit.
        'max_files_per_minute' => env('SAFEGUARD_RL_MAX_FILES', 60),
        'max_total_size_per_minute' => env('SAFEGUARD_RL_MAX_TOTAL', 200 * 1024 * 1024),
    ],

    /*
    |--------------------------------------------------------------------------
    | Quarantine of Rejected Files (opt-in)
    |--------------------------------------------------------------------------
    |
    | When enabled, a rejected file is copied to `path` with a sanitized JSON
    | metadata sidecar. Disabled by default. A quarantine failure never breaks
    | validation and never causes fail-open.
    |
    */

    'quarantine' => [
        'enabled' => env('SAFEGUARD_QUARANTINE', false),
        'path' => env('SAFEGUARD_QUARANTINE_PATH', null), // null => storage_path('app/safeguard-quarantine')
        'retention_days' => env('SAFEGUARD_QUARANTINE_RETENTION', 30),
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging & Reporting
    |--------------------------------------------------------------------------
    */

    'logging' => [
        'enabled' => env('SAFEGUARD_LOGGING', true),

        // Log channel. Validated at log time; falls back to the default channel
        // if the configured channel is undefined.
        'channel' => env('SAFEGUARD_LOG_CHANNEL', 'stack'),

        // Include detailed threat context (file metadata, threats).
        'detailed' => env('SAFEGUARD_LOG_DETAILED', true),

        // File hash for forensics: 'md5', 'sha256', or false to disable.
        'hash_algorithm' => env('SAFEGUARD_LOG_HASH', 'sha256'),
    ],
];
