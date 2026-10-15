<?php

namespace AppGuard\Stores;

use AppGuard\Core\Contracts\Store;
use Illuminate\Cache\Repository;

final class CacheStore implements Store
{
    public function __construct(private Repository $cache, private string $prefix = 'guard:')
    {
    }

    public function hit(string $key, int $ttl, int $by = 1): int
    {
        try {
            $key = $this->prefix . $key;
            $this->cache->add($key, 0, $ttl);
            return (int) $this->cache->increment($key, $by);
        } catch (\Throwable $e) {
            return 0; // Fail-open
        }
    }

    public function count(string $key): int
    {
        try {
            return (int) $this->cache->get($this->prefix . $key, 0);
        } catch (\Throwable $e) {
            return 0; // Fail-open
        }
    }

    public function put(string $key, int $value, int $ttl): void
    {
        try {
            $this->cache->put($this->prefix . $key, $value, $ttl);
        } catch (\Throwable $e) {
            // Fail-open
        }
    }

    public function has(string $key): bool
    {
        try {
            return (bool) $this->cache->has($this->prefix . $key);
        } catch (\Throwable $e) {
            return false; // Fail-open
        }
    }

    public function forget(string $key): void
    {
        try {
            $this->cache->forget($this->prefix . $key);
        } catch (\Throwable $e) {
            // Fail-open
        }
    }
}
