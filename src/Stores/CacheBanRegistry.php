<?php

namespace AppGuard\Stores;

use AppGuard\Core\BanRecord;
use AppGuard\Core\Contracts\BanRegistry;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Contracts\Cache\Repository as CacheRepository;

/**
 * Indeks ban berbasis cache store Guard (umumnya Redis).
 *
 * Seluruh record disimpan dalam satu key indeks (`guard:bans:index`) sehingga daftar ban
 * dapat dibaca dengan satu GET tanpa SCAN/KEYS. Penulisan memakai atomic lock (bila
 * driver mendukung) dan record kedaluwarsa dipangkas otomatis setiap kali indeks ditulis.
 */
final class CacheBanRegistry implements BanRegistry
{
    private const MAX_ENTRIES = 5000;

    public function __construct(
        private CacheRepository $cache,
        private string $key = 'guard:bans:index',
    ) {
    }

    public function record(BanRecord $ban): void
    {
        $this->mutate(function (array $index) use ($ban) {
            $index[$ban->id()] = $ban->toArray();

            return $index;
        });
    }

    public function remove(string $type, string $subject): void
    {
        $this->mutate(function (array $index) use ($type, $subject) {
            unset($index[BanRecord::key($type, $subject)]);

            return $index;
        });
    }

    public function find(string $type, string $subject): ?BanRecord
    {
        return $this->all()[BanRecord::key($type, $subject)] ?? null;
    }

    public function all(): array
    {
        try {
            $raw = (array) $this->cache->get($this->key, []);
        } catch (\Throwable $e) {
            return []; // Fail-open
        }

        $now = time();
        $out = [];
        foreach ($raw as $row) {
            if (! is_array($row)) {
                continue;
            }
            $ban = BanRecord::fromArray($row);
            if ($ban->subject !== '' && ! $ban->isExpired($now)) {
                $out[$ban->id()] = $ban;
            }
        }

        return $out;
    }

    private function mutate(callable $callback): void
    {
        $write = function () use ($callback) {
            $now = time();
            $index = array_filter(
                (array) $this->cache->get($this->key, []),
                fn ($row) => is_array($row) && (($row['expires_at'] ?? null) === null || (int) $row['expires_at'] > $now)
            );

            $index = $callback($index);

            if (count($index) > self::MAX_ENTRIES) {
                uasort($index, fn ($a, $b) => ($b['banned_at'] ?? 0) <=> ($a['banned_at'] ?? 0));
                $index = array_slice($index, 0, self::MAX_ENTRIES, true);
            }

            $index === []
                ? $this->cache->forget($this->key)
                : $this->cache->forever($this->key, $index);
        };

        try {
            $store = $this->cache->getStore();
            if ($store instanceof LockProvider) {
                try {
                    $store->lock($this->key . ':lock', 5)->block(2, $write);

                    return;
                } catch (LockTimeoutException $e) {
                    // Lanjut tanpa lock daripada kehilangan record
                }
            }

            $write();
        } catch (\Throwable $e) {
            // Fail-open: indeks gagal ditulis tidak boleh mengganggu request
        }
    }
}

