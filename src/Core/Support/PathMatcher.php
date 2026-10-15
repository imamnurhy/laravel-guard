<?php

namespace AppGuard\Core\Support;

final class PathMatcher
{
    public static function normalize(string $path): string
    {
        return strtolower(trim($path, '/'));
    }

    /** Return pattern yang cocok (wildcard ala fnmatch), atau null. */
    public static function matches(array $patterns, string $path): ?string
    {
        $path = self::normalize($path);

        foreach ($patterns as $pattern) {
            $norm = self::normalize($pattern);
            if (fnmatch($norm, $path) || fnmatch("*/{$norm}", $path) || str_ends_with($path, '/' . ltrim($norm, '*'))) {
                return $pattern;
            }
        }

        return null;
    }
}
