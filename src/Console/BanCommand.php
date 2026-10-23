<?php

namespace AppGuard\Console;

use AppGuard\Core\BanRecord;
use AppGuard\Core\Guard;
use AppGuard\Handlers\DefaultUserBanHandler;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\Console\Helper\TableStyle;

/**
 * Command terpadu untuk melihat, memeriksa, menyinkronkan, dan membuka blokir IP/user di terminal.
 *
 * Penggunaan:
 *   php artisan guard:ban                   # alias guard:ban list
 *   php artisan guard:ban list [--type=ip] [--search=...] [--limit=50] [--json]
 *   php artisan guard:ban show {subject}
 *   php artisan guard:ban check {subject}
 *   php artisan guard:ban stats [--json]
 *   php artisan guard:ban unban {subject?} [--type=] [--sync-db] [--force]
 *   php artisan guard:ban sync [--json]
 */
final class BanCommand extends Command
{
    protected $signature = 'guard:ban
        {action=list : Aksi: list | show | check | stats | unban | sync}
        {subject? : IP address atau ID pengguna (untuk show/check/unban)}
        {--type= : Filter tipe subject (ip atau user)}
        {--source= : Filter sumber/detektor pemicu}
        {--search= : Cari pada subject, alasan, atau IP}
        {--sort=newest : Urutan: newest | expiring | score}
        {--limit=50 : Batas jumlah baris yang ditampilkan}
        {--sync-db : Saat unban user, pulihkan juga status akun di database}
        {--force : Jalankan unban tanpa konfirmasi interaktif}
        {--json : Tampilkan output dalam format JSON}';

    protected $description = 'Monitoring dan manajemen daftar IP & pengguna yang diban/diblokir AppGuard (list, show, check, stats, unban, sync)';

    public function handle(Guard $guard, DefaultUserBanHandler $banHandler): int
    {
        $action = strtolower((string) $this->argument('action'));
        $subject = $this->argument('subject');

        // Jika pengguna memanggil `php artisan guard:ban 10.0.0.1`, perlakukan sebagai `check`
        if (! in_array($action, ['list', 'ls', 'show', 'info', 'check', 'stats', 'unban', 'unblock', 'sync'], true) && $subject === null) {
            $subject = $action;
            $action = 'check';
        }

        return match ($action) {
            'list', 'ls' => $this->handleList($guard),
            'show', 'info' => $this->handleShow($guard, (string) $subject),
            'check' => $this->handleCheck($guard, (string) $subject),
            'stats' => $this->handleStats($guard),
            'unban', 'unblock' => $this->handleUnban($guard, $banHandler, $subject ? (string) $subject : null),
            'sync' => $this->handleSync($guard, $banHandler),
            default => $this->unknownAction($action),
        };
    }

    private function handleList(Guard $guard): int
    {
        $records = $this->collectActiveBans($guard);

        $type = $this->normalizeType($this->option('type'));
        $source = strtolower(trim((string) $this->option('source')));
        $search = strtolower(trim((string) $this->option('search')));
        $sort = strtolower((string) $this->option('sort'));
        $limit = max(1, (int) $this->option('limit'));

        $filtered = array_filter($records, function (BanRecord $b) use ($type, $source, $search) {
            if ($type !== null && $b->type !== $type) {
                return false;
            }
            if ($source !== '' && strtolower($b->source) !== $source) {
                return false;
            }
            if ($search !== '') {
                $haystack = strtolower(implode(' ', [$b->subject, $b->label(), $b->reason, $b->source, (string) $b->ip]));
                if (! str_contains($haystack, $search)) {
                    return false;
                }
            }

            return true;
        });

        usort($filtered, fn (BanRecord $a, BanRecord $b) => match ($sort) {
            'expiring' => ($a->expiresAt ?? PHP_INT_MAX) <=> ($b->expiresAt ?? PHP_INT_MAX),
            'score' => $b->score <=> $a->score,
            default => $b->bannedAt <=> $a->bannedAt,
        });

        $total = count($filtered);
        $rows = array_slice($filtered, 0, $limit);

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'mode' => $guard->enforcing() ? 'enforce' : 'monitor',
                'total' => $total,
                'items' => array_map(fn (BanRecord $b) => $b->toArray() + ['remaining' => $b->remaining()], $rows),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->renderBanner($guard, count($records));

        if ($rows === []) {
            $this->line('  <fg=green>✓</> Tidak ada IP atau pengguna yang sedang diban/diblokir' . ($total !== count($records) ? ' (sesuai filter).' : '.'));
            $this->newLine();

            return self::SUCCESS;
        }

        $now = time();
        $tableRows = [];
        foreach ($rows as $i => $ban) {
            $tableRows[] = [
                $i + 1,
                $this->formatTypeBadge($ban->type),
                '<options=bold>' . $this->truncate($ban->label(), 26) . '</>',
                $this->formatScore($ban->score),
                '<fg=cyan>' . $this->truncate($ban->source ?: '-', 16) . '</>',
                $this->truncate($ban->reason ?: '-', 34),
                $ban->bannedAt > 0 ? date('Y-m-d H:i:s', $ban->bannedAt) : '-',
                $this->formatTtl($ban, $now),
            ];
        }

        $this->table(
            ['#', 'Tipe', 'Subject', 'Skor', 'Sumber', 'Alasan', 'Waktu Ban', 'Sisa TTL'],
            $tableRows,
            $this->boxTableStyle(),
        );

        if ($total > $limit) {
            $this->line("  <fg=gray>Menampilkan {$limit} dari {$total} entri. Gunakan --limit={$total} untuk melihat seluruhnya.</>");
        }
        $this->line('  <fg=gray>Tip: detail →</> <fg=yellow>php artisan guard:ban show {subject}</> <fg=gray>| buka blokir →</> <fg=yellow>php artisan guard:ban unban {subject}</>');
        $this->newLine();

        return self::SUCCESS;
    }

    private function handleShow(Guard $guard, string $subject): int
    {
        if ($subject === '') {
            $this->error('Argumen {subject} wajib diisi. Contoh: php artisan guard:ban show 192.168.1.10');

            return self::FAILURE;
        }

        $type = $this->resolveType($subject, $this->option('type'));
        $record = $this->findLiveRecord($guard, $type, $subject);
        $isBlocked = $type === BanRecord::TYPE_IP ? $guard->isBlocked($subject) : $guard->isUserBanned($subject);
        $score = $type === BanRecord::TYPE_IP ? $guard->scoreOf($subject) : $guard->scoreOfUser($subject);
        $forceLogout = $type === BanRecord::TYPE_USER && $guard->isUserForceLoggedOut($subject);

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'type' => $type,
                'subject' => $subject,
                'blocked' => $isBlocked,
                'force_logged_out' => $forceLogout,
                'score' => $score,
                'record' => $record?->toArray(),
                'remaining' => $record?->remaining(),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->newLine();
        $statusBadge = $isBlocked
            ? '<bg=red;fg=white;options=bold> ⛔ DIBLOKIR / BANNED </>'
            : ($forceLogout ? '<bg=yellow;fg=black;options=bold> ⚠ FORCE LOGOUT </>' : '<bg=green;fg=black;options=bold> ✓ AMAN / AKTIF </>');

        $this->line("  <options=bold>AppGuard Detail Subject</>  {$statusBadge}");
        $this->newLine();

        $detailRows = [
            ['Tipe', strtoupper($type)],
            ['Subject', $record ? $record->label() : $subject],
            ['Status Blokir', $isBlocked ? '<fg=red;options=bold>YA (Aktif di Store / Reputasi Tinggi)</>' : '<fg=green>Tidak</>'],
            ['Skor Reputasi Saat Ini', $this->formatScore(max($score, $record?->score ?? 0))],
            ['Sumber / Detektor', $record?->source ?: '-'],
            ['Alasan', $record?->reason ?: '-'],
            ['IP Terkait', $record?->ip ?: ($type === BanRecord::TYPE_IP ? $subject : '-')],
            ['Dibanned Pada', $record && $record->bannedAt > 0 ? date('Y-m-d H:i:s', $record->bannedAt) : '-'],
            ['Berakhir Pada', $record ? ($record->expiresAt ? date('Y-m-d H:i:s', $record->expiresAt) : 'Permanen') : '-'],
            ['Sisa Waktu (TTL)', $record && $isBlocked ? $this->formatTtl($record, time()) : '-'],
        ];

        // Cek status kolom database bila bertipe user
        if ($type === BanRecord::TYPE_USER) {
            foreach ($this->inspectUserDatabase($subject) as $col => $state) {
                $detailRows[] = ["DB ({$col})", $state];
            }
        }

        $this->table(['Atribut', 'Nilai'], $detailRows, $this->boxTableStyle());

        if ($isBlocked) {
            $this->line("  <fg=gray>Jalankan</> <fg=yellow>php artisan guard:ban unban {$subject}" . ($type === BanRecord::TYPE_USER ? ' --sync-db' : '') . '</> <fg=gray>untuk membuka blokir.</>');
        }
        $this->newLine();

        return self::SUCCESS;
    }

    private function handleCheck(Guard $guard, string $subject): int
    {
        if ($subject === '') {
            $this->error('Argumen {subject} wajib diisi. Contoh: php artisan guard:ban check 192.168.1.10');

            return self::FAILURE;
        }

        $type = $this->resolveType($subject, $this->option('type'));
        $isBlocked = $type === BanRecord::TYPE_IP ? $guard->isBlocked($subject) : $guard->isUserBanned($subject);
        $score = $type === BanRecord::TYPE_IP ? $guard->scoreOf($subject) : $guard->scoreOfUser($subject);
        $record = $this->findLiveRecord($guard, $type, $subject);

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'type' => $type,
                'subject' => $subject,
                'blocked' => $isBlocked,
                'score' => $score,
                'reason' => $record?->reason,
                'remaining' => $record?->remaining(),
            ], JSON_UNESCAPED_SLASHES));

            return $isBlocked ? self::FAILURE : self::SUCCESS;
        }

        if ($isBlocked) {
            $ttl = $record ? $this->formatDuration($record->remaining()) : 'aktif';
            $reason = $record && $record->reason !== '' ? " — {$record->reason}" : '';
            $this->line("⛔ <fg=red;options=bold>DIBLOKIR</> [{$type}: {$subject}] (skor: {$score}, sisa: {$ttl}){$reason}");

            return self::FAILURE;
        }

        $this->line("✅ <fg=green;options=bold>AMAN</> [{$type}: {$subject}] (skor reputasi: {$score})");

        return self::SUCCESS;
    }

    private function handleStats(Guard $guard): int
    {
        $records = $this->collectActiveBans($guard);

        $byType = [BanRecord::TYPE_IP => 0, BanRecord::TYPE_USER => 0];
        $bySource = [];
        foreach ($records as $ban) {
            $byType[$ban->type] = ($byType[$ban->type] ?? 0) + 1;
            $src = $ban->source ?: 'unknown';
            $bySource[$src] = ($bySource[$src] ?? 0) + 1;
        }
        arsort($bySource);

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'mode' => $guard->enforcing() ? 'enforce' : 'monitor',
                'total_active' => count($records),
                'by_type' => $byType,
                'by_source' => $bySource,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $total = count($records);
        $this->renderBanner($guard, $total);

        $this->table(
            ['Metrik', 'Jumlah'],
            [
                ['Total Ban/Blokir Aktif', '<options=bold>' . $total . '</>'],
                ['IP Terblokir', '<fg=magenta>' . $byType[BanRecord::TYPE_IP] . '</>'],
                ['Akun Pengguna Diban', '<fg=yellow>' . $byType[BanRecord::TYPE_USER] . '</>'],
            ],
            $this->boxTableStyle(),
        );

        if ($bySource !== []) {
            $sourceRows = [];
            foreach ($bySource as $src => $count) {
                $barLen = $total > 0 ? max(1, (int) round(($count / $total) * 20)) : 0;
                $bar = '<fg=cyan>' . str_repeat('█', $barLen) . '</>';
                $pct = $total > 0 ? round(($count / $total) * 100) : 0;
                $sourceRows[] = [$src, $count, "{$bar} {$pct}%"];
            }
            $this->table(['Sumber / Detektor', 'Jumlah', 'Proporsi'], $sourceRows, $this->boxTableStyle());
        }

        return self::SUCCESS;
    }

    private function handleUnban(Guard $guard, DefaultUserBanHandler $banHandler, ?string $subject): int
    {
        if ($subject === null || $subject === '') {
            $records = array_values($this->collectActiveBans($guard));
            if ($records === []) {
                $this->info('Tidak ada IP atau pengguna yang sedang diban.');

                return self::SUCCESS;
            }

            $choices = [];
            foreach ($records as $r) {
                $choices[$r->id()] = sprintf('[%s] %s — %s', strtoupper($r->type), $r->label(), $r->reason ?: $r->source);
            }
            $picked = $this->choice('Pilih subject yang akan dibuka blokirnya', $choices);
            [$type, $subject] = explode(':', (string) array_search($picked, $choices, true) ?: $picked, 2);
        } else {
            $type = $this->resolveType($subject, $this->option('type'));
        }

        if (! $this->option('force') && $this->input->isInteractive()) {
            if (! $this->confirm("Buka blokir {$type} '{$subject}'?", true)) {
                $this->line('Dibatalkan.');

                return self::SUCCESS;
            }
        }

        if ($type === BanRecord::TYPE_IP) {
            $guard->unblock($subject);
            $this->info("✓ Blokir IP {$subject} telah dihapus dan skor reputasi di-reset.");
        } else {
            $syncDb = (bool) $this->option('sync-db');
            $guard->unbanUser($subject);
            $banHandler->unban($subject, syncDb: $syncDb);
            $this->info("✓ Blokir pengguna ID {$subject} telah dihapus" . ($syncDb ? ' (status database disinkronkan).' : '.'));
        }

        return self::SUCCESS;
    }

    private function unknownAction(string $action): int
    {
        $this->error("Aksi tidak dikenal: '{$action}'. Gunakan: list, show, check, stats, unban, atau sync.");

        return self::FAILURE;
    }

    /**
     * Rekonsiliasi penuh snapshot indeks ban Redis lokal ↔ Control Plane,
     * serta mengeksekusi perintah tertunda (`unban_ip`, `unban_user`, `ban_ip`, `ban_user`) dari Control Plane.
     */
    private function handleSync(Guard $guard, DefaultUserBanHandler $banHandler): int
    {
        $records = array_values($this->collectActiveBans($guard));
        $snapshot = array_map(fn (BanRecord $b) => $b->toArray() + ['remaining' => $b->remaining()], $records);

        $client = app()->bound(\AppGuard\Core\ControlPlaneClient::class)
            ? app(\AppGuard\Core\ControlPlaneClient::class)
            : null;

        if (! $client || ! $client->isConfigured()) {
            if ($this->option('json')) {
                $this->line((string) json_encode(['synced' => false, 'local_count' => count($snapshot), 'items' => $snapshot]));
            } else {
                $this->warn('Control Plane belum dikonfigurasi. Indeks lokal telah dibersihkan (' . count($snapshot) . ' ban aktif).');
            }

            return self::SUCCESS;
        }

        try {
            $body = (string) json_encode([
                'tenant' => $client->getAppKey(),
                'synced_at' => date('c'),
                'bans' => $snapshot,
            ]);
            $response = $client->request('POST', '/bans/sync', [
                'headers' => ['Content-Type' => 'application/json'],
                'body' => $body,
            ]);

            $applied = 0;
            if ($response->successful()) {
                $data = (array) $response->json();
                foreach ((array) ($data['commands'] ?? []) as $cmd) {
                    if ($this->applyRemoteCommand($guard, $banHandler, (array) $cmd)) {
                        $applied++;
                    }
                }
            }

            if ($this->option('json')) {
                $this->line((string) json_encode([
                    'synced' => $response->successful(),
                    'local_count' => count($snapshot),
                    'commands_applied' => $applied,
                ]));
            } else {
                $this->info('✓ Rekonsiliasi ban selesai (' . count($snapshot) . " ban aktif dikirim, {$applied} perintah Control Plane diterapkan).");
            }

            return self::SUCCESS;
        } catch (\Throwable $e) {
            $this->warn('Fail-open: gagal menyinkronkan ban ke Control Plane (' . $e->getMessage() . ').');

            return self::SUCCESS;
        }
    }

    /** @param array<string, mixed> $cmd */
    private function applyRemoteCommand(Guard $guard, DefaultUserBanHandler $banHandler, array $cmd): bool
    {
        $action = (string) ($cmd['action'] ?? $cmd['event'] ?? '');
        $subject = (string) ($cmd['subject'] ?? $cmd['ip'] ?? $cmd['user_id'] ?? '');
        if ($subject === '') {
            return false;
        }

        return match ($action) {
            'unban_ip', 'unblock' => ($guard->unblock($subject, 'control_plane', (string) ($cmd['reason'] ?? 'Control Plane Unban')) === null),
            'unban_user' => (function () use ($guard, $banHandler, $subject, $cmd) {
                $guard->unbanUser($subject, 'control_plane', (string) ($cmd['reason'] ?? 'Control Plane Unban'));
                $banHandler->unban($subject, syncDb: (bool) ($cmd['sync_db'] ?? true));
                return true;
            })(),
            'ban_ip', 'block' => ($guard->block($subject, (int) ($cmd['ttl'] ?? 3600), (string) ($cmd['reason'] ?? 'Control Plane Ban'), 'control_plane') === null),
            default => false,
        };
    }

    /**
     * Ambil semua ban dari indeks dan verifikasi masih aktif di Store;
     * entri yatim (key TTL sudah habis) langsung dibersihkan dari indeks.
     *
     * @return array<string, BanRecord>
     */
    private function collectActiveBans(Guard $guard): array
    {
        $registry = $guard->banRegistry();
        $active = [];

        foreach ($guard->bans() as $id => $ban) {
            $stillBlocked = $ban->type === BanRecord::TYPE_IP
                ? $guard->isBlocked($ban->subject)
                : $guard->isUserBanned($ban->subject);

            if ($stillBlocked) {
                $active[$id] = $ban;
            } else {
                $registry?->remove($ban->type, $ban->subject);
            }
        }

        return $active;
    }

    private function findLiveRecord(Guard $guard, string $type, string $subject): ?BanRecord
    {
        $record = $guard->findBan($type, $subject);
        if ($record !== null) {
            return $record;
        }

        // Fallback ke metadata legacy guard:user_banned:{id} bila ada
        if ($type === BanRecord::TYPE_USER && class_exists(Cache::class)) {
            $meta = Cache::get("guard:user_banned:{$subject}");
            if (is_array($meta)) {
                return new BanRecord(
                    type: BanRecord::TYPE_USER,
                    subject: $subject,
                    reason: (string) ($meta['reason'] ?? ''),
                    source: 'user_ban',
                    score: (int) ($meta['score'] ?? 100),
                    bannedAt: isset($meta['banned_at']) ? (int) strtotime((string) $meta['banned_at']) : 0,
                    expiresAt: null,
                    ip: isset($meta['ip']) ? (string) $meta['ip'] : null,
                );
            }
        }

        // Fallback bila IP memiliki skor reputasi aktif yang mencapai threshold
        if ($type === BanRecord::TYPE_IP) {
            $score = $guard->scoreOf($subject);
            $strictThreshold = (int) (config('guard.profiles.strict.block') ?? 70);
            $globalThreshold = (int) (config('guard.thresholds.block') ?? 100);
            if ($score >= $strictThreshold) {
                return new BanRecord(
                    type: BanRecord::TYPE_IP,
                    subject: $subject,
                    reason: $score >= $globalThreshold
                        ? "Skor reputasi ({$score}) mencapai ambang batas blokir global"
                        : "Skor reputasi ({$score}) mencapai ambang batas blokir profil strict (seperti /login)",
                    source: 'reputation',
                    score: $score,
                    bannedAt: time(),
                    expiresAt: null,
                    ip: $subject,
                );
            }
        }

        return null;
    }

    /** @return array<string, string> */
    private function inspectUserDatabase(string $userId): array
    {
        $modelClass = config('guard.user_ban.model');
        $attributes = (array) config('guard.user_ban.attributes', []);
        if (! $modelClass || ! class_exists($modelClass) || $attributes === []) {
            return [];
        }

        try {
            $user = $modelClass::find($userId);
            if (! $user) {
                return [];
            }

            $out = [];
            foreach ($attributes as $col => $bannedVal) {
                $curr = $user->{$col} ?? null;
                $out[$col] = ((int) $curr === (int) $bannedVal)
                    ? "<fg=red>BANNED ({$curr})</>"
                    : "<fg=green>AKTIF ({$curr})</>";
            }

            return $out;
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function renderBanner(Guard $guard, int $activeCount): void
    {
        $mode = $guard->enforcing()
            ? '<bg=red;fg=white;options=bold> ENFORCE </>'
            : '<bg=yellow;fg=black;options=bold> MONITOR </>';
        $store = (string) (config('guard.store') ?: config('cache.default', 'default'));
        $countBadge = $activeCount > 0 ? "<fg=red;options=bold>{$activeCount} aktif</>" : '<fg=green>0 aktif</>';

        $this->newLine();
        $this->line("  🛡️  <options=bold>AppGuard Ban Monitor</>  {$mode}  <fg=gray>store:</> <fg=cyan>{$store}</>  <fg=gray>total:</> {$countBadge}");
        $this->newLine();
    }

    private function normalizeType(mixed $type): ?string
    {
        $t = strtolower(trim((string) $type));

        return in_array($t, [BanRecord::TYPE_IP, BanRecord::TYPE_USER], true) ? $t : null;
    }

    private function resolveType(string $subject, mixed $typeOption): string
    {
        if ($normalized = $this->normalizeType($typeOption)) {
            return $normalized;
        }

        return filter_var($subject, FILTER_VALIDATE_IP) !== false ? BanRecord::TYPE_IP : BanRecord::TYPE_USER;
    }

    private function formatTypeBadge(string $type): string
    {
        return $type === BanRecord::TYPE_IP
            ? '<fg=magenta;options=bold>IP</>'
            : '<fg=yellow;options=bold>USER</>';
    }

    private function formatScore(int $score): string
    {
        return match (true) {
            $score >= 100 => "<fg=red;options=bold>{$score}</>",
            $score >= 50 => "<fg=yellow>{$score}</>",
            default => (string) $score,
        };
    }

    private function formatTtl(BanRecord $ban, int $now): string
    {
        $rem = $ban->remaining($now);
        if ($rem === null) {
            return '<fg=red;options=bold>PERMANENT</>';
        }
        if ($rem <= 0) {
            return '<fg=gray>expired</>';
        }

        $text = $this->formatDuration($rem);

        return $rem <= 300 ? "<fg=yellow>{$text}</>" : "<fg=red>{$text}</>";
    }

    private function formatDuration(?int $seconds): string
    {
        if ($seconds === null) {
            return 'permanen';
        }
        if ($seconds <= 0) {
            return '0s';
        }

        $d = intdiv($seconds, 86400);
        $h = intdiv($seconds % 86400, 3600);
        $m = intdiv($seconds % 3600, 60);
        $s = $seconds % 60;

        if ($d > 0) {
            return "{$d}d {$h}h";
        }
        if ($h > 0) {
            return "{$h}h {$m}m";
        }
        if ($m > 0) {
            return "{$m}m {$s}s";
        }

        return "{$s}s";
    }

    private function truncate(string $value, int $max): string
    {
        $clean = preg_replace('/\s+/', ' ', trim($value)) ?? '';

        return mb_strlen($clean) > $max ? mb_substr($clean, 0, $max - 1) . '…' : $clean;
    }

    private function boxTableStyle(): TableStyle
    {
        $style = new TableStyle();
        $style
            ->setHorizontalBorderChars('─')
            ->setVerticalBorderChars('│', '│')
            ->setCrossingChars('┼', '┌', '┬', '┐', '┤', '┘', '┴', '└', '├')
            ->setCellHeaderFormat('<fg=cyan;options=bold>%s</>');

        return $style;
    }
}

