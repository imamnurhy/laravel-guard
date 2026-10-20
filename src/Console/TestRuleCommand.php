<?php

namespace AppGuard\Console;

use AppGuard\Core\Guard;
use AppGuard\Core\RequestContext;
use Illuminate\Console\Command;
use Symfony\Component\Console\Helper\TableStyle;

/**
 * Uji sebuah request/payload terhadap detektor & aturan AppGuard tanpa menyimpan skor ke Redis.
 */
final class TestRuleCommand extends Command
{
    protected $signature = 'guard:test-rule
        {path=/ : Path URL yang akan diuji (mis. /.env atau /search)}
        {--method=GET : HTTP method (GET, POST, PUT, DELETE)}
        {--ip=198.51.100.10 : Alamat IP simulasi}
        {--user= : User ID simulasi}
        {--input=* : Pasangan key=value input (dapat diulang, mis. --input="q=\' union select 1--")}
        {--profile= : Profile override (strict, balanced, monitor)}
        {--json : Tampilkan hasil dalam format JSON}';

    protected $description = 'Uji simulasi request & payload terhadap detektor AppGuard (dry-run di terminal)';

    public function handle(Guard $guard): int
    {
        $path = '/' . ltrim((string) $this->argument('path'), '/');
        $method = strtoupper((string) $this->option('method'));
        $ip = (string) $this->option('ip');
        $userId = $this->option('user') !== null ? (string) $this->option('user') : null;

        $inputs = [];
        foreach ((array) $this->option('input') as $pair) {
            if (str_contains((string) $pair, '=')) {
                [$k, $v] = explode('=', (string) $pair, 2);
                $inputs[trim($k)] = $v;
            } else {
                $inputs['payload'] = (string) $pair;
            }
        }

        $ctx = new RequestContext(
            ip: $ip,
            method: $method,
            path: $path,
            userAgent: 'GuardTestCLI/1.0',
            userId: $userId,
            attributes: ['inputs' => $inputs],
        );

        $signals = [];
        foreach ($guard->detectors() as $detector) {
            foreach ($detector->inspect($ctx) as $signal) {
                $signals[] = $signal;
            }
        }

        $resolved = $guard->resolveProfileOverrides($path, array_filter([
            'profile' => $this->option('profile'),
        ]));
        $totalScore = array_sum(array_map(fn ($s) => $s->score, $signals));
        $wouldAction = match (true) {
            $totalScore >= $resolved['block'] => 'block',
            $totalScore >= $resolved['throttle'] => 'throttle',
            default => 'allow',
        };

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'path' => $path,
                'method' => $method,
                'score' => $totalScore,
                'thresholds' => ['throttle' => $resolved['throttle'], 'block' => $resolved['block']],
                'action' => $wouldAction,
                'signals' => array_map(fn ($s) => [
                    'detector' => $s->detector,
                    'score' => $s->score,
                    'reason' => $s->reason,
                ], $signals),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->newLine();
        $badge = match ($wouldAction) {
            'block' => '<bg=red;fg=white;options=bold> ⛔ BLOCK </>',
            'throttle' => '<bg=yellow;fg=black;options=bold> ⚠ THROTTLE </>',
            default => '<bg=green;fg=black;options=bold> ✓ ALLOW </>',
        };
        $this->line("  🧪 <options=bold>AppGuard Rule Dry-Run</>  {$badge}  <fg=gray>{$method} {$path}</>  <fg=gray>skor:</> <options=bold>{$totalScore}</> <fg=gray>(throttle={$resolved['throttle']}, block={$resolved['block']})</>");
        $this->newLine();

        if ($signals === []) {
            $this->line('  <fg=green>✓</> Tidak ada detektor yang terpicu oleh request ini.');
            $this->newLine();

            return self::SUCCESS;
        }

        $rows = [];
        foreach ($signals as $i => $s) {
            $rows[] = [$i + 1, "<fg=cyan>{$s->detector}</>", "<fg=red;options=bold>+{$s->score}</>", $s->reason];
        }

        $style = (new TableStyle())
            ->setHorizontalBorderChars('─')
            ->setVerticalBorderChars('│', '│')
            ->setCrossingChars('┼', '┌', '┬', '┐', '┤', '┘', '┴', '└', '├')
            ->setCellHeaderFormat('<fg=cyan;options=bold>%s</>');

        $this->table(['#', 'Detektor', 'Skor', 'Alasan'], $rows, $style);

        return self::SUCCESS;
    }
}

