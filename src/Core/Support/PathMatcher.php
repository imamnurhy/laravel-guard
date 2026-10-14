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
            if (fnmatch(self::normalize($pattern), $path)) {
                return $pattern;
            }
        }

        return null;
    }
}
