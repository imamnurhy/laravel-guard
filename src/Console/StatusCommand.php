<?php

namespace AppGuard\Console;

use AppGuard\Core\Guard;
use Illuminate\Console\Command;

final class StatusCommand extends Command
{
    protected $signature = 'guard:status {ip?}';
    protected $description = 'Lihat status operasional sistem keamanan AppGuard atau status spesifik sebuah IP';

    public function handle(Guard $guard): int
    {
        $ip = $this->argument('ip');

        if ($ip) {
            $this->info("AppGuard Status untuk IP: {$ip}");
            $this->line('mode     : ' . ($guard->enforcing() ? 'enforce' : 'monitor'));
            $this->line('blocked  : ' . ($guard->isBlocked($ip) ? 'yes' : 'no'));
            $this->line('reputasi : ' . $guard->scoreOf($ip));

            return self::SUCCESS;
        }

        $this->info('AppGuard System Status:');
        $this->line('enabled  : ' . ($guard->enabled() ? 'true' : 'false'));
        $this->line('mode     : ' . ($guard->enforcing() ? 'enforce' : 'monitor'));
        $this->line('fail_open: ' . ($guard->failOpen() ? 'true' : 'false'));
        $this->line('store    : ' . (config('guard.store') ?: config('cache.default', 'file')));

        return self::SUCCESS;
    }
}
