<?php

namespace AppGuard\Core\Contracts;

interface Store
{
    /** Tambah counter (fixed window; TTL diset saat key pertama dibuat). Return nilai terbaru. */
    public function hit(string $key, int $ttl, int $by = 1): int;

    public function count(string $key): int;

    public function put(string $key, int $value, int $ttl): void;

    public function has(string $key): bool;

    public function forget(string $key): void;
}
