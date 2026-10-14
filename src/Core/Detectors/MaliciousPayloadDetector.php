<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

/**
 * Deteksi pola serangan umum seperti SQL Injection dan Cross-Site Scripting (XSS).
 */
final class MaliciousPayloadDetector extends AbstractDetector
{
    private array $sqliPatterns = [
        '/\bunion\s+(all\s+)?select\b/i',
        '/\bselect\s+.+\s+from\s+information_schema\b/i',
        '/\b(benchmark|sleep)\s*\(\s*\d+\s*\)/i',
        '/\bwaitfor\s+delay\s+[\'"]/i',
        '/[\'"]\s+or\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1/i',
        '/[\'"]\s+or\s+1\s*=\s*1\s*(--|#|\/\*)/i',
    ];

    private array $xssPatterns = [
        '/<script\b[^>]*>/i',
        '/javascript:\s*[a-z0-9_]+\s*\(/i',
        '/<svg\b[^>]*\bonload\s*=/i',
        '/<img\b[^>]*\bonerror\s*=/i',
        '/<iframe\b[^>]*>/i',
    ];

    public function __construct(private array $config = [])
    {
    }

    public function name(): string
    {
        return 'malicious_payload';
    }

    public function inspect(RequestContext $ctx): array
    {
        $inputs = $ctx->attributes['inputs'] ?? [];
        $safeFields = $this->config['safe_fields'] ?? [];
        $signals = [];

        $sqliScore = (int) ($this->config['sqli_score'] ?? 100);
        $xssScore = (int) ($this->config['xss_score'] ?? 50);

        foreach ($inputs as $key => $val) {
            if (in_array($key, $safeFields, true) || !is_string($val) || $val === '') {
                continue;
            }

            // 1. Cek SQL Injection
            foreach ($this->sqliPatterns as $pattern) {
                if (preg_match($pattern, $val)) {
                    $signals[] = new Signal('sqli', $sqliScore, "SQL Injection payload detected in '{$key}'", persist: true);
                    return $signals;
                }
            }

            // 2. Cek XSS
            foreach ($this->xssPatterns as $pattern) {
                if (preg_match($pattern, $val)) {
                    $signals[] = new Signal('xss', $xssScore, "XSS payload detected in '{$key}'", persist: true);
                    return $signals;
                }
            }
        }

        return [];
    }
}
