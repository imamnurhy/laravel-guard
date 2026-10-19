<?php

namespace AppGuard\Console;

use AppGuard\Core\Guard;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;

final class UserStatusCommand extends Command
{
    protected $signature = 'guard:user-status {userId : ID pengguna yang akan dicek statusnya}';
    protected $description = 'Lihat status blokir, skor reputasi, dan metadata keamanan seorang pengguna';

    public function handle(Guard $guard): int
    {
        $userId = $this->argument('userId');

        $isBanned = $guard->isUserBanned($userId);
        $score = $guard->scoreOfUser($userId);
        $bannedMeta = Cache::get("guard:user_banned:{$userId}");

        $this->info("AppGuard Status Pengguna ID: {$userId}");
        $this->line('terblokir : ' . ($isBanned ? '<fg=red;options=bold>YA (BANNED)</>' : '<fg=green>TIDAK (AKTIF)</>'));
        $this->line('skor penalti : ' . $score);

        if ($bannedMeta && is_array($bannedMeta)) {
            $this->newLine();
            $this->line('<fg=yellow>Detail Pemblokiran Terakhir:</>');
            $this->line('alasan    : ' . ($bannedMeta['reason'] ?? '-'));
            $this->line('waktu     : ' . ($bannedMeta['banned_at'] ?? '-'));
            $this->line('ip pelaku : ' . ($bannedMeta['ip'] ?? '-'));
        }

        // Cek status database jika model terkonfigurasi
        $modelClass = config('guard.user_ban.model');
        $attributes = config('guard.user_ban.attributes', []);
        if ($modelClass && class_exists($modelClass)) {
            $user = $modelClass::find($userId);
            if ($user) {
                $this->newLine();
                $this->line('<fg=cyan>Status Database Model (' . class_basename($modelClass) . '):</>');
                foreach ($attributes as $col => $expectedBannedVal) {
                    $currVal = $user->{$col} ?? null;
                    $statusStr = ((int)$currVal === (int)$expectedBannedVal) ? '<fg=red>BANNED (' . $currVal . ')</>' : '<fg=green>AKTIF (' . $currVal . ')</>';
                    $this->line("kolom {$col} : {$statusStr}");
                }
            }
        }

        return self::SUCCESS;
    }
}
