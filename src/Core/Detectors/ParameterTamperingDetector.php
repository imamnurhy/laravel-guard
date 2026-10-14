<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

/**
 * Deteksi manipulasi parameter sensitif (privilege escalation, role tampering, status manipulation).
 */
final class ParameterTamperingDetector extends AbstractDetector
{
    public function __construct(private array $config = [])
    {
    }

    public function name(): string
    {
        return 'parameter_tampering';
    }

    public function inspect(RequestContext $ctx): array
    {
        // Hanya periksa request mutasi (POST, PUT, PATCH, DELETE)
        if (in_array(strtoupper($ctx->method), ['GET', 'HEAD', 'OPTIONS'], true)) {
            return [];
        }

        $forbiddenFields = $this->config['forbidden_fields'] ?? [
            'is_admin',
            'role',
            'role_id',
            'status_id',
            'is_superuser',
        ];

        $inputs = $ctx->attributes['inputs'] ?? [];
        $score = (int) ($this->config['score'] ?? 35);
        $signals = [];

        foreach ($forbiddenFields as $field) {
            if (array_key_exists($field, $inputs)) {
                $signals[] = new Signal(
                    $this->name(),
                    $score,
                    "forbidden sensitive parameter tampering '{$field}'",
                    persist: true
                );
            }
        }

        return $signals;
    }
}
