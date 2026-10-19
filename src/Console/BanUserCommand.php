<?php

namespace AppGuard\Console;

use AppGuard\Handlers\DefaultUserBanHandler;
use Illuminate\Console\Command;

final class BanUserCommand extends Command
{
    protected $signature = 'guard:ban-user {userId : ID pengguna yang akan diblokir} {--reason=Manual Admin Ban : Alasan pemblokiran akun}';
    protected $description = 'Blokir akun pengguna secara manual di layer database dan cache AppGuard';

    public function handle(DefaultUserBanHandler $banHandler): int
    {
        $userId = $this->argument('userId');
        $reason = (string) $this->option('reason');

        $modelClass = config('guard.user_ban.model');
        $user = ($modelClass && class_exists($modelClass)) ? $modelClass::find($userId) : $userId;

        if (! $user) {
            $this->error("Pengguna ID {$userId} tidak ditemukan di database.");
            return self::FAILURE;
        }

        $banHandler->ban($user, 100, $reason);

        $this->info("Pengguna ID {$userId} berhasil diblokir (100 poin, alasan: '{$reason}').");

        return self::SUCCESS;
    }
}
