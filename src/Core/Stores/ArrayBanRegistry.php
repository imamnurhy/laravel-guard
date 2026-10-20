<?php

namespace AppGuard\Core\Stores;

use AppGuard\Core\BanRecord;
use AppGuard\Core\Contracts\BanRegistry;

/** Registry ban in-memory untuk test. Jangan dipakai di production. */
final class ArrayBanRegistry implements BanRegistry
{
    /** @var array<string, BanRecord> */
    private array $items = [];

    public function record(BanRecord $ban): void
    {
        $this->items[$ban->id()] = $ban;
    }

    public function remove(string $type, string $subject): void
    {
        unset($this->items[BanRecord::key($type, $subject)]);
    }

    public function find(string $type, string $subject): ?BanRecord
    {
        return $this->all()[BanRecord::key($type, $subject)] ?? null;
    }

    public function all(): array
    {
        $now = time();
        $this->items = array_filter($this->items, fn (BanRecord $b) => ! $b->isExpired($now));

        return $this->items;
    }
}

