<?php

namespace AppGuard\Core\Contracts;

use AppGuard\Core\BanRecord;

/**
 * Indeks ban/blokir aktif. Implementasi wajib fail-open (tidak boleh melempar exception).
 */
interface BanRegistry
{
    /** Simpan/timpa record ban (key unik: type + subject). */
    public function record(BanRecord $ban): void;

    public function remove(string $type, string $subject): void;

    public function find(string $type, string $subject): ?BanRecord;

    /** @return array<string, BanRecord> Record yang belum kedaluwarsa, di-key "type:subject". */
    public function all(): array;
}

