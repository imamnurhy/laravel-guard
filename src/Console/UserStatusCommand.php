<?php

namespace AppGuard\Console;

use AppGuard\Core\BanRecord;
use AppGuard\Core\Guard;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\Console\Helper\TableStyle;

final class UserStatusCommand extends Command
{
    protected $signature = 'guard:user-status
        {userId : ID pengguna yang akan dicek statusnya}
        {--json : Tampilkan output dalam format JSON}';

    protected $description = 'Lihat status blokir, skor reputasi, dan metadata keamanan seorang pengguna dalam bentuk tabel';

    public function handle(Guard $guard): int
    {
        $userId = (string) $this->argument('userId');

        $isBanned = $guard->isUserBanned($userId);
        $forceLogout = $guard->isUserForceLoggedOut($userId);
        $score = $guard->scoreOfUser($userId);
        $record = $guard->findBan(BanRecord::TYPE_USER, $userId);
        $bannedMeta = class_exists(Cache::class) ? Cache::get("guard:user_banned:{$userId}") : null;

        $reason = $record?->reason ?: (is_array($bannedMeta) ? (string) ($bannedMeta['reason'] ?? '') : '');
        $ip = $record?->ip ?: (is_array($bannedMeta) ? (string) ($bannedMeta['ip'] ?? '') : '');
        $bannedAt = $record && $record->bannedAt > 0
            ? date('Y-m-d H:i:s', $record->bannedAt)
            : (is_array($bannedMeta) ? (string) ($bannedMeta['banned_at'] ?? '') : '');
        $source = $record?->source ?: ($isBanned ? 'user_ban' : '-');

        $dbColumns = $this->inspectUserDatabase($userId);

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'user_id' => $userId,
                'banned' => $isBanned,
                'force_logged_out' => $forceLogout,
                'score' => $score,
                'source' => $source,
                'reason' => $reason ?: null,
                'ip' => $ip ?: null,
                'banned_at' => $bannedAt ?: null,
                'remaining' => $record?->remaining(),
                'database' => $dbColumns['raw'],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $statusBadge = $isBanned
            ? '<bg=red;fg=white;options=bold> ⛔ DIBLOKIR / BANNED </>'
            : ($forceLogout ? '<bg=yellow;fg=black;options=bold> ⚠ FORCE LOGOUT </>' : '<bg=green;fg=black;options=bold> ✓ AMAN / AKTIF </>');

        $this->newLine();
        $this->line("  👤 <options=bold>AppGuard Status Pengguna ID:</> <fg=cyan>{$userId}</>  {$statusBadge}");
        $this->newLine();

        $scoreFormatted = match (true) {
            $score >= 100 => "<fg=red;options=bold>{$score}</>",
            $score >= 50 => "<fg=yellow>{$score}</>",
            default => "<fg=green>{$score}</>",
        };

        $rows = [
            ['User ID', "<options=bold>{$userId}</>"],
            ['Status Blokir (Cache)', $isBanned ? '<fg=red;options=bold>YA (BANNED)</>' : '<fg=green>TIDAK (AKTIF)</>'],
            ['Status Force Logout', $forceLogout ? '<fg=yellow;options=bold>YA (Sesi Diputus)</>' : '<fg=green>Tidak</>'],
            ['Skor Penalti Reputasi', $scoreFormatted],
            ['Sumber / Detektor', $source ?: '-'],
            ['Alasan Pemblokiran', $reason ?: '-'],
            ['IP Pelaku Terakhir', $ip ?: '-'],
            ['Waktu Pemblokiran', $bannedAt ?: '-'],
            ['Sisa Waktu (TTL)', $record && $isBanned ? ($record->remaining() !== null ? $record->remaining() . 's' : 'PERMANENT') : '-'],
        ];

        foreach ($dbColumns['formatted'] as $col => $val) {
            $rows[] = ["DB ({$col})", $val];
        }

        $this->table(['Atribut', 'Nilai'], $rows, $this->boxTableStyle());
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * @return array{raw: array<string, mixed>, formatted: array<string, string>}
     */
    private function inspectUserDatabase(string $userId): array
    {
        $modelClass = config('guard.user_ban.model');
        $attributes = (array) config('guard.user_ban.attributes', []);
        if (! $modelClass || ! class_exists($modelClass) || $attributes === []) {
            return ['raw' => [], 'formatted' => []];
        }

        try {
            $user = $modelClass::find($userId);
            if (! $user) {
                return ['raw' => [], 'formatted' => []];
            }

            $raw = [];
            $formatted = [];
            foreach ($attributes as $col => $expectedBannedVal) {
                $currVal = $user->{$col} ?? null;
                $isBannedCol = (int) $currVal === (int) $expectedBannedVal;
                $raw[$col] = [
                    'value' => $currVal,
                    'banned' => $isBannedCol,
                ];
                $formatted[$col] = $isBannedCol
                    ? "<fg=red;options=bold>BANNED ({$currVal})</>"
                    : "<fg=green>AKTIF ({$currVal})</>";
            }

            return ['raw' => $raw, 'formatted' => $formatted];
        } catch (\Throwable) {
            return ['raw' => [], 'formatted' => []];
        }
    }

    private function boxTableStyle(): TableStyle
    {
        return (new TableStyle())
            ->setHorizontalBorderChars('─')
            ->setVerticalBorderChars('│', '│')
            ->setCrossingChars('┼', '┌', '┬', '┐', '┤', '┘', '┴', '└', '├')
            ->setCellHeaderFormat('<fg=cyan;options=bold>%s</>');
    }
}
