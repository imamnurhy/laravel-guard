<?php

namespace AppGuard\Core\Stores;

use AppGuard\Core\Contracts\Store;

/** Store in-memory untuk test. Jangan dipakai di production. */
final class ArrayStore implements Store
{
    private array $data = [];
    private array $expires = [];

    public function hit(string $key, int $ttl, int $by = 1): int
    {
        $this->gc($key);
        if (! isset($this->data[$key])) {
            $this->data[$key] = 0;
            $this->expires[$key] = time() + $ttl;
        }

        return $this->data[$key] += $by;
    }

    public function count(string $key): int
    {
        $this->gc($key);

        return $this->data[$key] ?? 0;
    }

    public function put(string $key, int $value, int $ttl): void
    {
        $this->data[$key] = $value;
        $this->expires[$key] = time() + $ttl;
    }

    public function has(string $key): bool
    {
        $this->gc($key);

        return isset($this->data[$key]);
    }

    public function forget(string $key): void
    {
        unset($this->data[$key], $this->expires[$key]);
    }

    private function gc(string $key): void
    {
        if (isset($this->expires[$key]) && $this->expires[$key] <= time()) {
            unset($this->data[$key], $this->expires[$key]);
        }
    }
}
