<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\Contracts\Store;
use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;
use AppGuard\Core\Support\PathMatcher;

/**
 * Brute force multi-dimensi: per IP, per identifier (email/username), dan per pasangan.
 * Counter diisi lewat recordFailure() (dipanggil listener event Failed milik adapter).
 * Pengecekan hanya berlaku di path login, agar sisa situs tidak ikut terkunci.
 */
final class BruteForceDetector extends AbstractDetector
{
    public function __construct(private Store $store, private array $config = [])
    {
    }

    public function name(): string
    {
        return 'brute_force';
    }

    public function inspect(RequestContext $ctx): array
    {
        if (PathMatcher::matches($this->config['paths'] ?? [], $ctx->path) === null) {
            return [];
        }

        $signals = [];

        if ($this->store->count($this->ipKey($ctx->ip)) >= ($this->config['max_per_ip'] ?? 20)) {
            $signals[] = new Signal($this->name(), $this->config['score_ip'] ?? 100, 'too many failed logins from this IP');
        }

        if ($ctx->identifier !== null) {
            if ($this->store->count($this->idKey($ctx->identifier)) >= ($this->config['max_per_identifier'] ?? 8)) {
                // skor lebih rendah: tanpa sinyal lain hanya throttle, supaya penyerang tidak bisa
                // mengunci pemilik akun sah dengan mudah
                $signals[] = new Signal($this->name(), $this->config['score_identifier'] ?? 60, 'too many failed logins for this account');
            }

            if ($this->store->count($this->pairKey($ctx->ip, $ctx->identifier)) >= ($this->config['max_per_pair'] ?? 5)) {
                $signals[] = new Signal($this->name(), $this->config['score_pair'] ?? 100, 'too many failed logins for this IP + account');
            }
        }

        return $signals;
    }

    public function recordFailure(string $ip, ?string $identifier): void
    {
        $ttl = (int) ($this->config['window'] ?? 900);

        $this->store->hit($this->ipKey($ip), $ttl);

        if ($identifier !== null) {
            $this->store->hit($this->idKey($identifier), $ttl);
            $this->store->hit($this->pairKey($ip, $identifier), $ttl);
        }
    }

    /** Login sukses: reset counter pasangan IP + akun saja (counter IP & akun tetap jalan). */
    public function recordSuccess(string $ip, ?string $identifier): void
    {
        if ($identifier !== null) {
            $this->store->forget($this->pairKey($ip, $identifier));
        }
    }

    private function ipKey(string $ip): string
    {
        return "bf:ip:{$ip}";
    }

    private function idKey(string $identifier): string
    {
        return 'bf:id:' . $this->hash($identifier);
    }

    private function pairKey(string $ip, string $identifier): string
    {
        return "bf:pair:{$ip}:" . $this->hash($identifier);
    }

    private function hash(string $identifier): string
    {
        return sha1(strtolower(trim($identifier)));
    }
}
