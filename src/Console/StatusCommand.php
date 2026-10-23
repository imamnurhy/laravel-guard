<?php

namespace AppGuard\Console;

use AppGuard\Core\BanRecord;
use AppGuard\Core\Guard;
use Illuminate\Console\Command;
use Symfony\Component\Console\Helper\TableStyle;

final class StatusCommand extends Command
{
    protected $signature = 'guard:status
        {ip? : Alamat IP yang akan diperiksa status reputasi dan pemblokirannya}
        {--json : Tampilkan output dalam format JSON}';

    protected $description = 'Lihat status operasional sistem keamanan AppGuard atau status spesifik sebuah IP dalam bentuk tabel';

    public function handle(Guard $guard): int
    {
        $ip = $this->argument('ip');

        if ($ip !== null && $ip !== '') {
            return $this->handleIpStatus($guard, (string) $ip);
        }

        return $this->handleSystemStatus($guard);
    }

    private function handleIpStatus(Guard $guard, string $ip): int
    {
        $score = $guard->scoreOf($ip);
        $globalBlock = (int) (config('guard.thresholds.block') ?? 100);
        $strictBlock = (int) (config('guard.profiles.strict.block') ?? 70);
        $hasExplicit = $guard->hasExplicitBlock($ip);
        $isBlocked = $guard->isBlocked($ip);
        $record = $guard->findBan(BanRecord::TYPE_IP, $ip);

        $blockedState = match (true) {
            $hasExplicit => 'yes (explicit block)',
            $score >= $globalBlock => 'yes (skor reputasi mencapai batas global)',
            $score >= $strictBlock => 'yes (terblokir pada rute profil strict seperti login)',
            default => 'no',
        };

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'ip' => $ip,
                'mode' => $guard->enforcing() ? 'enforce' : 'monitor',
                'blocked' => $isBlocked,
                'explicit_block' => $hasExplicit,
                'blocked_state' => $blockedState,
                'score' => $score,
                'thresholds' => [
                    'global_block' => $globalBlock,
                    'strict_block' => $strictBlock,
                ],
                'record' => $record?->toArray(),
                'remaining' => $record?->remaining(),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $badge = $isBlocked
            ? '<bg=red;fg=white;options=bold> ⛔ DIBLOKIR </>'
            : '<bg=green;fg=black;options=bold> ✓ AMAN </>';

        $this->newLine();
        $this->line("  🛡️  <options=bold>AppGuard IP Status:</> <fg=cyan>{$ip}</>  {$badge}");
        $this->newLine();

        $scoreColor = match (true) {
            $score >= $strictBlock => "<fg=red;options=bold>{$score}</>",
            $score >= (int) (config('guard.thresholds.throttle') ?? 50) => "<fg=yellow>{$score}</>",
            default => "<fg=green>{$score}</>",
        };

        $rows = [
            ['Alamat IP', "<options=bold>{$ip}</>"],
            ['Mode Guard', $guard->enforcing() ? '<fg=red;options=bold>enforce</>' : '<fg=yellow>monitor</>'],
            ['Status Blokir', $isBlocked ? "<fg=red;options=bold>{$blockedState}</>" : '<fg=green>no (Aman)</>'],
            ['Skor Reputasi', "{$scoreColor} <fg=gray>(ambang batas global: {$globalBlock}, strict: {$strictBlock})</>"],
            ['Sumber / Detektor', $record?->source ?: '-'],
            ['Alasan Terakhir', $record?->reason ?: '-'],
            ['Waktu Ban', $record && $record->bannedAt > 0 ? date('Y-m-d H:i:s', $record->bannedAt) : '-'],
            ['Sisa TTL', $record && $isBlocked ? ($record->remaining() !== null ? $record->remaining() . 's' : 'PERMANENT') : '-'],
        ];

        $this->table(['Atribut', 'Nilai'], $rows, $this->boxTableStyle());
        $this->newLine();

        return self::SUCCESS;
    }

    private function handleSystemStatus(Guard $guard): int
    {
        $storeDriver = (string) (config('guard.store') ?: config('cache.default', 'file'));
        $telemetryDriver = strtolower((string) config('guard.vulnerability.driver', 'jsonl'));
        $bufferedCount = $guard->vulnerabilityStore()?->count() ?? 0;
        $activeBans = count($guard->bans());
        $detectorCount = count($guard->detectors());
        $globalThrottle = (int) (config('guard.thresholds.throttle') ?? 50);
        $globalBlock = (int) (config('guard.thresholds.block') ?? 100);
        $strictBlock = (int) (config('guard.profiles.strict.block') ?? 70);

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'enabled' => $guard->enabled(),
                'mode' => $guard->enforcing() ? 'enforce' : 'monitor',
                'fail_open' => $guard->failOpen(),
                'store' => $storeDriver,
                'telemetry_driver' => $telemetryDriver,
                'telemetry_buffered' => $bufferedCount,
                'detectors_count' => $detectorCount,
                'active_bans' => $activeBans,
                'thresholds' => [
                    'throttle' => $globalThrottle,
                    'block' => $globalBlock,
                    'strict_block' => $strictBlock,
                ],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $modeBadge = $guard->enforcing()
            ? '<bg=red;fg=white;options=bold> ENFORCE </>'
            : '<bg=yellow;fg=black;options=bold> MONITOR </>';

        $this->newLine();
        $this->line("  🛡️  <options=bold>AppGuard System Status</>  {$modeBadge}");
        $this->newLine();

        $rows = [
            ['Status Proteksi (enabled)', $guard->enabled() ? '<fg=green;options=bold>true (Aktif)</>' : '<fg=red;options=bold>false (Nonaktif)</>'],
            ['Mode Operasional (mode)', $guard->enforcing() ? '<fg=red;options=bold>enforce</>' : '<fg=yellow>monitor</>'],
            ['Kebijakan Fail-Open', $guard->failOpen() ? '<fg=green>true (Fail-Open)</>' : '<fg=yellow>false (Fail-Closed)</>'],
            ['Reputation Store', "<fg=cyan>{$storeDriver}</> <fg=gray>(prefix: " . config('guard.key_prefix', 'guard:') . ')</>'],
            ['Telemetry / Incident Store', "<fg=cyan>{$telemetryDriver}</> <fg=gray>(antrean buffer: {$bufferedCount} item)</>"],
            ['Ambang Batas Skor', "throttle: {$globalThrottle} | block: {$globalBlock} | strict: {$strictBlock}"],
            ['Detektor WAF Terdaftar', "{$detectorCount} detektor aktif"],
            ['Total Ban Aktif (IP & User)', $activeBans > 0 ? "<fg=red;options=bold>{$activeBans} aktif</>" : '<fg=green>0 aktif</>'],
        ];

        $this->table(['Komponen / Parameter', 'Nilai / Status'], $rows, $this->boxTableStyle());
        $this->newLine();

        return self::SUCCESS;
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
