<?php

namespace AppGuard\Console;

use AppGuard\Core\Guard;
use Illuminate\Console\Command;

final class UnblockCommand extends Command
{
    protected $signature = 'guard:unblock {ip}';
    protected $description = 'Hapus blokir manual dan reset skor reputasi sebuah IP';

    public function handle(Guard $guard): int
    {
        $guard->unblock($this->argument('ip'));
        $this->info("Unblocked {$this->argument('ip')}.");

        return self::SUCCESS;
    }
}
