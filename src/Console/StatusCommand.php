<?php

namespace AppGuard\Console;

use AppGuard\Core\Guard;
use Illuminate\Console\Command;

final class StatusCommand extends Command
{
    protected $signature = 'guard:status {ip}';
    protected $description = 'Lihat status blokir dan skor reputasi sebuah IP';

    public function handle(Guard $guard): int
    {
        $ip = $this->argument('ip');
        $this->line('mode     : ' . ($guard->enforcing() ? 'enforce' : 'monitor'));
        $this->line('blocked  : ' . ($guard->isBlocked($ip) ? 'yes' : 'no'));
        $this->line('reputasi : ' . $guard->scoreOf($ip));

        return self::SUCCESS;
    }
}
