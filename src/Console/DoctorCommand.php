<?php

namespace AppGuard\Console;

use AppGuard\Core\Contracts\Store;
use AppGuard\Core\Contracts\VulnerabilityStore;
use AppGuard\Core\ControlPlaneClient;
use AppGuard\Core\Guard;
use AppGuard\Stores\JsonFileVulnerabilityStore;
use Illuminate\Console\Command;
use Symfony\Component\Console\Helper\TableStyle;

/**
 * Diagnostik konfigurasi, koneksi cache/Redis, telemetry/incident store, dan integrasi Control Plane.
 */
final class DoctorCommand extends Command
{
    protected $signature = 'guard:doctor {--json : Tampilkan hasil diagnostik dalam format JSON}';
    protected $description = 'Periksa kesehatan konfigurasi, cache store, telemetry store, dan koneksi Control Plane AppGuard';

    public function handle(Guard $guard, Store $store, ControlPlaneClient $client, VulnerabilityStore $vulnStore): int
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

        // 4. Telemetry & Incident Store (multi-driver: jsonl, redis, cache, array, null)
        $telemetryDriver = strtolower((string) config('guard.vulnerability.driver', 'jsonl'));
        $checks[] = $this->checkTelemetryStore($telemetryDriver, $vulnStore, $storeOk);

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

    /**
     * @return array{name: string, ok: bool, detail: string}
     */
    private function checkTelemetryStore(string $driver, VulnerabilityStore $vulnStore, bool $cacheStoreOk): array
    {
        $buffered = $vulnStore->count();
        $key = (string) config('guard.vulnerability.key', 'telemetry:incidents');

        return match ($driver) {
            'redis' => [
                'name' => 'Telemetry / Incident Store',
                'ok' => true,
                'detail' => "driver=redis, key={$key}, buffered={$buffered} item",
            ],
            'cache' => [
                'name' => 'Telemetry / Incident Store',
                'ok' => $cacheStoreOk,
                'detail' => "driver=cache, key={$key}, buffered={$buffered} item",
            ],
            'array', 'memory' => [
                'name' => 'Telemetry / Incident Store',
                'ok' => true,
                'detail' => "driver=array (in-memory), buffered={$buffered} item",
            ],
            'null', 'none', 'off', '' => [
                'name' => 'Telemetry / Incident Store',
                'ok' => true,
                'detail' => 'driver=null (nonaktif)',
            ],
            default => (function () use ($buffered) {
                $rawDatasetPath = (string) config('guard.vulnerability.dataset_path', storage_path('app/guard'));
                $datasetPath = JsonFileVulnerabilityStore::resolveFilePath($rawDatasetPath);
                $datasetDir = dirname($datasetPath);
                $dirWritable = is_dir($datasetDir) ? is_writable($datasetDir) : is_writable(dirname($datasetDir));

                return [
                    'name' => 'Telemetry / Incident Store',
                    'ok' => $dirWritable,
                    'detail' => "driver=jsonl, path={$datasetPath} (" . ($dirWritable ? 'writable' : 'tidak writable') . "), buffered={$buffered} item",
                ];
            })(),
        };
    }
}
