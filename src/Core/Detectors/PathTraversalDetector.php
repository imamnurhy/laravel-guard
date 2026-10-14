<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

/**
 * Deteksi Path Traversal (../, ..\, %2e%2e, null-byte, dan direktori sistem).
 */
final class PathTraversalDetector extends AbstractDetector
{
    private array $patterns = [
        '/\.\.\//',
        '/\.\.\\\\/',
        '/%2e%2e(%2f|\/|%5c|\\\\)/i',
        '/%252e%252e/i',
        '/\x00|%00/',
        '/\/etc\/(passwd|shadow|hosts)/i',
        '/[a-zA-Z]:(\/|\\\\)windows/i',
    ];

    public function __construct(private array $config = [])
    {
    }

    public function name(): string
    {
        return 'path_traversal';
    }

    public function inspect(RequestContext $ctx): array
    {
        $score = (int) ($this->config['score'] ?? 50);
        $signals = [];

        // 1. Periksa path URL
        foreach ($this->patterns as $pattern) {
            if (preg_match($pattern, $ctx->path)) {
                $signals[] = new Signal($this->name(), $score, 'path traversal pattern in URI path', persist: true);
                return $signals;
            }
        }

        // 2. Periksa parameter input jika tersedia di attributes
        $inputs = $ctx->attributes['inputs'] ?? [];
        foreach ($inputs as $key => $val) {
            if (!is_string($val) || $val === '') {
                continue;
            }

            foreach ($this->patterns as $pattern) {
                if (preg_match($pattern, $val)) {
                    $signals[] = new Signal($this->name(), $score, "path traversal in parameter '{$key}'", persist: true);
                    return $signals;
                }
            }
        }

        return [];
    }
}
