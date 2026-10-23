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

            $score = $guard->scoreOf($ip);
            $globalBlock = (int) (config('guard.thresholds.block') ?? 100);
            $strictBlock = (int) (config('guard.profiles.strict.block') ?? 70);

            $blockedText = match (true) {
                $guard->hasExplicitBlock($ip) => 'yes',
                $score >= $globalBlock => 'yes (skor reputasi mencapai batas global)',
                $score >= $strictBlock => 'yes (terblokir pada rute profil strict seperti login)',
                default => 'no',
            };

            $this->line('blocked  : ' . $blockedText);
            $this->line("reputasi : {$score} (ambang batas global: {$globalBlock}, strict: {$strictBlock})");

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
