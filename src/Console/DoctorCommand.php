<?php

namespace AppGuard\Console;

use AppGuard\Core\Contracts\Store;
use AppGuard\Core\ControlPlaneClient;
use AppGuard\Core\Guard;
use Illuminate\Console\Command;
use Symfony\Component\Console\Helper\TableStyle;

/**
 * Diagnostik konfigurasi, koneksi cache/Redis, file dataset, dan integrasi Control Plane.
 */
final class DoctorCommand extends Command
{
    protected $signature = 'guard:doctor {--json : Tampilkan hasil diagnostik dalam format JSON}';
    protected $description = 'Periksa kesehatan konfigurasi, cache store, dataset, dan koneksi Control Plane AppGuard';

    public function handle(Guard $guard, Store $store, ControlPlaneClient $client): int
    {
        $checks = [];

        // 1. Status & mode
        $checks[] = [
            'name' => 'Guard Enabled & Mode',
            'ok' => $guard->enabled(),
            'detail' => 'enabled=' . ($guard->enabled() ? 'true' : 'false') . ', mode=' . ($guard->enforcing() ? 'enforce' : 'monitor') . ', fail_open=' . ($guard->failOpen() ? 'true' : 'false'),
        ];

        // 2. Cache / Store read-write
        $probeKey = 'doctor:probe:' . uniqid();
        $store->put($probeKey, 1, 10);
        $storeOk = $store->has($probeKey);
        $store->forget($probeKey);
        $storeDriver = (string) (config('guard.store') ?: config('cache.default', 'default'));
        $checks[] = [
            'name' => 'Cache / Reputation Store',
            'ok' => $storeOk,
            'detail' => "driver={$storeDriver}, prefix=" . config('guard.key_prefix', 'guard:'),
        ];

        // 3. Detektor aktif
        $detCount = count($guard->detectors());
        $checks[] = [
            'name' => 'Detektor Terdaftar',
            'ok' => $detCount > 0,
            'detail' => "{$detCount} detektor aktif",
        ];

        // 4. Direktori dataset JSONL
        $rawDatasetPath = (string) config('guard.vulnerability.dataset_path', storage_path('app/guard'));
        $datasetPath = \AppGuard\Stores\JsonFileVulnerabilityStore::resolveFilePath($rawDatasetPath);
        $datasetDir = dirname($datasetPath);
        $dirWritable = is_dir($datasetDir) ? is_writable($datasetDir) : is_writable(dirname($datasetDir));
        $checks[] = [
            'name' => 'Dataset Forensik (JSONL)',
            'ok' => $dirWritable,
            'detail' => $datasetPath . ($dirWritable ? ' (writable)' : ' (tidak writable)'),
        ];

        // 5. Control Plane
        $cpConfigured = $client->isConfigured();
        $checks[] = [
            'name' => 'Control Plane Credentials',
            'ok' => $cpConfigured,
            'detail' => $cpConfigured ? ('url=' . $client->getBaseUrl() . ', key=' . $client->getAppKey()) : 'Belum dikonfigurasi (opsional untuk standalone)',
        ];

        $allCriticalOk = $checks[0]['ok'] && $checks[1]['ok'] && $checks[2]['ok'] && $checks[3]['ok'];

        if ($this->option('json')) {
            $this->line((string) json_encode(['healthy' => $allCriticalOk, 'checks' => $checks], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return $allCriticalOk ? self::SUCCESS : self::FAILURE;
        }

        $this->newLine();
        $this->line('  🩺 <options=bold>AppGuard Doctor — System Health Check</>');
        $this->newLine();

        $rows = array_map(fn (array $c) => [
            $c['ok'] ? '<fg=green;options=bold>✓ OK</>' : '<fg=yellow;options=bold>⚠ WARN</>',
            $c['name'],
            $c['detail'],
        ], $checks);

        $style = (new TableStyle())
            ->setHorizontalBorderChars('─')
            ->setVerticalBorderChars('│', '│')
            ->setCrossingChars('┼', '┌', '┬', '┐', '┤', '┘', '┴', '└', '├')
            ->setCellHeaderFormat('<fg=cyan;options=bold>%s</>');

        $this->table(['Status', 'Komponen', 'Detail'], $rows, $style);

        return $allCriticalOk ? self::SUCCESS : self::FAILURE;
    }
}

