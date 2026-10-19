<?php

namespace AppGuard\Console;

use AppGuard\Core\Guard;
use AppGuard\Handlers\DefaultUserBanHandler;
use Illuminate\Console\Command;

final class UnbanUserCommand extends Command
{
    protected $signature = 'guard:unban-user {userId : ID pengguna yang akan dibuka blokirnya} {--sync-db : Sinkronkan pemulihan status pengguna di database}';
    protected $description = 'Buka blokir akun pengguna di layer cache AppGuard dan opsional sinkronkan ke database';

    public function handle(Guard $guard, DefaultUserBanHandler $banHandler): int
    {
        $userId = $this->argument('userId');
        $syncDb = (bool) $this->option('sync-db');

        $guard->unbanUser($userId);
        if ($syncDb) {
            $banHandler->unban($userId, syncDb: true);
        }

        $this->info("Berhasil membuka blokir akun pengguna ID: {$userId} di layer cache AppGuard.");
        if ($syncDb) {
            $this->line("Status pengguna di database berhasil disinkronkan ke aktif.");
        }

        return self::SUCCESS;
    }
}
