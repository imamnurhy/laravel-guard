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

        $allKeys = $this->collectAllKeys($inputs);

        foreach ($forbiddenFields as $field) {
            if (in_array($field, $allKeys, true)) {
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

    /**
     * Mengumpulkan seluruh nama key input termasuk yang berada dalam struktur bersarang.
     */
    private function collectAllKeys(array $inputs): array
    {
        $keys = [];
        foreach ($inputs as $key => $val) {
            $keys[] = (string) $key;
            if (is_array($val)) {
                $keys = array_merge($keys, $this->collectAllKeys($val));
            }
        }
        return array_unique($keys);
    }
}
