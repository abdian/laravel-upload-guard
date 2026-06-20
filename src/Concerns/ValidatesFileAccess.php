<?php

namespace Abdian\UploadGuard\Concerns;

/**
 * ValidatesFileAccess — confines file access to allowed directories and rejects
 * symlinks and null-byte paths (TOCTOU / path-injection hardening).
 *
 * Boundary rules:
 *   - null bytes are rejected BEFORE realpath() (no ValueError);
 *   - prefix comparison requires a trailing separator (no sibling-prefix bypass
 *     such as /storage/app-evil matching /storage/app);
 *   - an explicitly-empty allow-list fails closed (reject), never allow-all;
 *   - defaults include the system temp dir, PHP's upload_tmp_dir, and storage/app.
 *
 * NOTE: validating the PHP temp file does NOT by itself close the temp->storage
 * time-of-check/time-of-use window. Use validateDestinationPath() immediately
 * before moving a validated upload to its final location.
 */
trait ValidatesFileAccess
{
    protected function validateFileAccess(string $path): bool
    {
        // 1. Null-byte check first — before any realpath() call.
        if (str_contains($path, "\0")) {
            return false;
        }

        // 2. Reject symbolic links when enabled.
        if ($this->getSecurityConfig('check_symlinks', true) && is_link($path)) {
            return false;
        }

        // 3. Must resolve to a real path.
        $realPath = realpath($path);
        if ($realPath === false) {
            return false;
        }

        // 4. Resolve the allow-list.
        $allowedPaths = $this->resolveAllowedPaths();

        // Fail closed on an empty allow-list.
        if (empty($allowedPaths)) {
            return false;
        }

        foreach ($allowedPaths as $allowedPath) {
            $realAllowed = realpath($allowedPath);
            if ($realAllowed === false) {
                continue;
            }
            if ($this->isWithin($realPath, $realAllowed)) {
                return true;
            }
        }

        return false;
    }

    protected function getFileAccessFailureReason(string $path): string
    {
        if (str_contains($path, "\0")) {
            return 'Invalid path: null byte detected';
        }
        if ($this->getSecurityConfig('check_symlinks', true) && is_link($path)) {
            return 'Symbolic link detected';
        }
        if (realpath($path) === false) {
            return 'Unable to resolve file path';
        }
        if (empty($this->resolveAllowedPaths())) {
            return 'No allowed upload paths configured';
        }

        return 'File path outside allowed directories';
    }

    /**
     * Validate a (possibly attacker-influenced) destination path before a move.
     *
     * Rejects null bytes, path traversal in either separator style, and
     * destinations that resolve outside the allowed roots or via a symlinked
     * parent directory.
     *
     * @param  array<string>|null  $allowedRoots
     */
    public function validateDestinationPath(string $destination, ?array $allowedRoots = null): bool
    {
        if ($destination === '' || str_contains($destination, "\0")) {
            return false;
        }

        $normalized = str_replace('\\', '/', $destination);

        // Reject explicit traversal segments.
        foreach (explode('/', $normalized) as $segment) {
            if ($segment === '..') {
                return false;
            }
        }

        $roots = $allowedRoots ?? $this->resolveAllowedPaths();
        if (empty($roots)) {
            return false;
        }

        // The parent directory must exist, must not be a symlink, and the
        // resolved parent must sit within an allowed root.
        $parent = \dirname($destination);
        if (is_link($parent)) {
            return false;
        }
        $realParent = realpath($parent);
        if ($realParent === false) {
            return false;
        }

        foreach ($roots as $root) {
            $realRoot = realpath($root);
            if ($realRoot === false) {
                continue;
            }
            if ($this->isWithin($realParent, $realRoot) || $this->pathsEqual($realParent, $realRoot)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<string>
     */
    protected function resolveAllowedPaths(): array
    {
        $configured = $this->getSecurityConfig('allowed_upload_paths', null);

        // null => auto defaults. An explicit array (even empty) is honored as-is.
        if ($configured === null) {
            return $this->getDefaultAllowedPaths();
        }

        return is_array($configured) ? $configured : [];
    }

    /**
     * @return array<string>
     */
    protected function getDefaultAllowedPaths(): array
    {
        $paths = [];

        $tempDir = sys_get_temp_dir();
        if (! empty($tempDir)) {
            $paths[] = $tempDir;
        }

        $uploadTmp = ini_get('upload_tmp_dir');
        if (is_string($uploadTmp) && $uploadTmp !== '') {
            $paths[] = $uploadTmp;
        }

        if (function_exists('storage_path')) {
            try {
                $storagePath = storage_path('app');
                if (! empty($storagePath)) {
                    $paths[] = $storagePath;
                }
            } catch (\Throwable) {
                // ignore
            }
        }

        return array_values(array_unique($paths));
    }

    private function isWithin(string $real, string $allowedReal): bool
    {
        $a = rtrim(str_replace('\\', '/', $real), '/');
        $b = rtrim(str_replace('\\', '/', $allowedReal), '/');

        if ($this->isWindows()) {
            $a = strtolower($a);
            $b = strtolower($b);
        }

        if ($a === $b) {
            return true;
        }

        return str_starts_with($a . '/', $b . '/');
    }

    private function pathsEqual(string $a, string $b): bool
    {
        $a = rtrim(str_replace('\\', '/', $a), '/');
        $b = rtrim(str_replace('\\', '/', $b), '/');
        if ($this->isWindows()) {
            return strtolower($a) === strtolower($b);
        }

        return $a === $b;
    }

    private function isWindows(): bool
    {
        return DIRECTORY_SEPARATOR === '\\';
    }

    protected function getSecurityConfig(string $key, mixed $default = null): mixed
    {
        if (function_exists('config') && function_exists('app')) {
            try {
                return config("safeguard.security.{$key}", $default) ?? $default;
            } catch (\Throwable) {
                return $default;
            }
        }

        return $default;
    }
}
