<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\Contracts\Store;
use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

/**
 * Detektor Anomali Adaptif:
 * 1. Shannon Entropy (keacakan tinggi / encrypted shellcode / obfuscated payload)
 * 2. URL Scanner Fuzzing (pemindaian masif URL berbeda dalam window singkat)
 */
final class AnomalyDetector extends AbstractDetector
{
    public function __construct(private Store $store, private array $config = [])
    {
    }

    public function name(): string
    {
        return 'anomaly';
    }

    public function inspect(RequestContext $ctx): array
    {
        $signals = [];

        // 1. Cek Shannon Entropy pada input
        $entropyThreshold = (float) ($this->config['entropy_threshold'] ?? 4.5);
        $minLen = (int) ($this->config['entropy_min_length'] ?? 120);
        $safeFields = $this->config['safe_fields'] ?? [];
        $inputs = $ctx->attributes['inputs'] ?? [];

        foreach ($inputs as $key => $val) {
            if (in_array($key, $safeFields, true) || !is_string($val) || strlen($val) < $minLen) {
                continue;
            }

            // Abaikan Data URI gambar
            if (str_starts_with($val, 'data:image/')) {
                continue;
            }

            $entropy = $this->calculateShannonEntropy($val);
            if ($entropy >= $entropyThreshold) {
                $signals[] = new Signal(
                    'high_entropy',
                    (int) ($this->config['entropy_score'] ?? 35),
                    "parameter '{$key}' has abnormal shannon entropy ({$entropy} >= {$entropyThreshold})",
                    persist: true
                );
                break;
            }
        }

        return $signals;
    }

    public function observe(RequestContext $ctx, int $status): array
    {
        // Hanya rekam status error client 404/403
        if (!in_array($status, [403, 404], true)) {
            return [];
        }

        $window = (int) ($this->config['fuzzing_window'] ?? 30);
        $threshold = (int) ($this->config['fuzzing_threshold'] ?? 15);
        $pathHash = substr(md5($ctx->path), 0, 8);

        // Catat unique hit path
        $key = "fuzz:ip:{$ctx->ip}:{$pathHash}";
        if ($this->store->has($key)) {
            return [];
        }
        $this->store->put($key, 1, $window);

        // Counter unique endpoints hit
        $count = $this->store->hit("fuzz_cnt:ip:{$ctx->ip}", $window);
        if ($count >= $threshold) {
            return [new Signal(
                'scanner_fuzzing',
                (int) ($this->config['fuzzing_score'] ?? 50),
                "massive scanner/fuzzing detected ({$count} distinct paths in {$window}s)",
                persist: true
            )];
        }

        return [];
    }

    /**
     * Algoritma Shannon Entropy: H(X) = -sum(P(x) * log2(P(x)))
     */
    public function calculateShannonEntropy(string $str): float
    {
        $len = strlen($str);
        if ($len === 0) {
            return 0.0;
        }

        $frequencies = count_chars($str, 1);
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return round($entropy, 4);
    }
}
