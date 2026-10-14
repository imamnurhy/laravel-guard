<?php

namespace AppGuard\Console;

use AppGuard\Core\Guard;
use Illuminate\Console\Command;

final class BlockCommand extends Command
{
    protected $signature = 'guard:block {ip} {--minutes=60}';
    protected $description = 'Blokir IP secara manual';

    public function handle(Guard $guard): int
    {
        $guard->block($this->argument('ip'), (int) $this->option('minutes') * 60);
        $this->info("Blocked {$this->argument('ip')} for {$this->option('minutes')} minutes.");

        return self::SUCCESS;
    }
}
