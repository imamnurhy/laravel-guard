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
        $key = $this->prefix . $key;

        $this->cache->add($key, 0, $ttl);

        return (int) $this->cache->increment($key, $by);
    }

    public function count(string $key): int
    {
        return (int) $this->cache->get($this->prefix . $key, 0);
    }

    public function put(string $key, int $value, int $ttl): void
    {
        $this->cache->put($this->prefix . $key, $value, $ttl);
    }

    public function has(string $key): bool
    {
        return $this->cache->has($this->prefix . $key);
    }

    public function forget(string $key): void
    {
        $this->cache->forget($this->prefix . $key);
    }
}
