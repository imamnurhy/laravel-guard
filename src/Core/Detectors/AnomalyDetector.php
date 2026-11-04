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
        $entropyThreshold = (float) ($this->config['entropy_threshold'] ?? 4.8);
        $minLen = (int) ($this->config['entropy_min_length'] ?? 150);
        $safeFields = $this->config['safe_fields'] ?? [];
        $inputs = $ctx->attributes['inputs'] ?? [];

        $flattened = $this->flattenInputs($inputs, $safeFields);

        foreach ($flattened as $key => $val) {
            if (strlen($val) < $minLen) {
                continue;
            }

            // Abaikan Data URI file/gambar/dokumen umum
            if (str_starts_with($val, 'data:')) {
                continue;
            }

            // Abaikan jika string merupakan payload JSON terstruktur yang valid atau base64-encoded JSON (misal: token enkripsi Laravel / JWT)
            if ($this->isValidJson($val) || $this->isBase64Json($val)) {
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

    /**
     * Memeriksa apakah string merupakan JSON terstruktur valid (array atau object).
     */
    private function isValidJson(string $val): bool
    {
        $trimmed = trim($val);
        $len = strlen($trimmed);
        if ($len < 2) {
            return false;
        }

        $first = $trimmed[0];
        $last = $trimmed[$len - 1];

        if (($first !== '{' || $last !== '}') && ($first !== '[' || $last !== ']')) {
            return false;
        }

        if (function_exists('json_validate')) {
            return json_validate($trimmed);
        }

        json_decode($trimmed);
        return json_last_error() === JSON_ERROR_NONE;
    }

    /**
     * Memeriksa apakah string merupakan JSON terstruktur valid yang di-encode base64 (misal: Laravel encrypted payload atau JWT).
     */
    private function isBase64Json(string $val): bool
    {
        $trimmed = trim($val);
        $len = strlen($trimmed);

        if ($len < 4) {
            return false;
        }

        // Cek bagian jika token JWT (dipisahkan tanda titik)
        if (str_contains($trimmed, '.')) {
            $parts = explode('.', $trimmed);
            if (count($parts) >= 2) {
                $firstDecoded = base64_decode(strtr($parts[0], '-_', '+/'), true);
                if ($firstDecoded && $this->isValidJson($firstDecoded)) {
                    return true;
                }
            }
        }

        // Cek format base64 standar (seperti Laravel Encrypter output: base64(json))
        if (! preg_match('/^[A-Za-z0-9+\/_-]+={0,2}$/', $trimmed)) {
            return false;
        }

        $decoded = base64_decode($trimmed, true);
        if ($decoded === false) {
            return false;
        }

        return $this->isValidJson($decoded);
    }

    /**
     * Memeriksa apakah field cocok dengan daftar safe_fields (termasuk wildcard fnmatch).
     */
    private function isSafeField(string $key, string $fullKey, array $safeFields): bool
    {
        foreach ($safeFields as $pattern) {
            if ($key === $pattern || $fullKey === $pattern) {
                return true;
            }
            if (str_contains($pattern, '*') && (fnmatch($pattern, $key) || fnmatch($pattern, $fullKey))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Mengurai input bersarang menjadi flat array string.
     */
    private function flattenInputs(array $inputs, array $safeFields, string $prefix = ''): array
    {
        $result = [];

        foreach ($inputs as $key => $val) {
            $fullKey = $prefix === '' ? (string)$key : "{$prefix}.{$key}";

            if ($this->isSafeField((string)$key, $fullKey, $safeFields)) {
                continue;
            }

            if (is_array($val)) {
                $result = array_merge($result, $this->flattenInputs($val, $safeFields, $fullKey));
            } elseif (is_string($val) && $val !== '') {
                $result[$fullKey] = $val;
            }
        }

        return $result;
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
