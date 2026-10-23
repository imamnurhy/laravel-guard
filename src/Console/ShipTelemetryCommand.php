<?php

namespace AppGuard\Console;

use AppGuard\Core\Contracts\VulnerabilityStore;
use AppGuard\Core\ControlPlaneClient;
use Illuminate\Console\Command;

final class ShipTelemetryCommand extends Command
{
    protected $signature = 'guard:ship-telemetry {--batch-size=100 : Jumlah rekaman per batch pengiriman}';
    protected $description = 'Kirim batch rekaman telemetri insiden dari buffer aktif (jsonl, redis, atau cache) ke Centralized Control Plane';

    public function handle(ControlPlaneClient $client, VulnerabilityStore $store): int
    {
        $driver = strtolower((string) config('guard.vulnerability.driver', 'jsonl'));
        $batchSize = max(1, (int) $this->option('batch-size'));

        $chunk = $store->peekBatch($batchSize);
        if ($chunk === []) {
            $this->info("Buffer telemetri (driver: {$driver}) kosong. Tidak ada data yang dikirim.");

            return self::SUCCESS;
        }

        if (! $client->isConfigured()) {
            $this->warn('Konfigurasi Control Plane belum lengkap. Pengiriman buffer ditunda.');

            return self::SUCCESS;
        }

        $batch = self::formatBatch($chunk);
        if ($batch === []) {
            $store->acknowledgeBatch(count($chunk));

            return self::SUCCESS;
        }

        $rawBody = (string) json_encode(['batch' => $batch]);

        try {
            $response = $client->request('POST', '/telemetry/ingest', [
                'headers' => ['Content-Type' => 'application/json'],
                'body' => $rawBody,
            ]);

            if ($response->successful()) {
                $store->acknowledgeBatch(count($chunk));

                $this->info('✓ Berhasil mengirim ' . count($batch) . " rekaman telemetri (driver: {$driver}) ke Control Plane.");

                return self::SUCCESS;
            }

            $this->warn("Gagal mengirim telemetri. Status {$response->status()}: " . $response->body());

            return self::FAILURE;
        } catch (\Throwable $e) {
            $this->warn("Gagal menghubungi Control Plane: {$e->getMessage()}. Data tetap aman di buffer ({$driver}).");

            return self::SUCCESS;
        }
    }

    /**
     * Format daftar insiden mentah menjadi skema batch `/telemetry/ingest` Control Plane.
     *
     * @param array<int, array<string, mixed>> $chunk
     * @return array<int, array<string, mixed>>
     */
    public static function formatBatch(array $chunk): array
    {
        $batch = [];
        $fallbackNow = function_exists('now') ? now()->toIso8601String() : date('c');

        foreach ($chunk as $decoded) {
            if (! is_array($decoded)) {
                continue;
            }

            $batch[] = [
                'ip_address' => $decoded['ip'] ?? $decoded['ip_address'] ?? '127.0.0.1',
                'violation_type' => $decoded['type'] ?? $decoded['violation_type'] ?? 'unknown',
                'ban_type' => $decoded['ban_type'] ?? null,
                'subject' => $decoded['subject'] ?? $decoded['user_id'] ?? $decoded['ip'] ?? null,
                'user_id' => $decoded['user_id'] ?? null,
                'score' => (int) ($decoded['score'] ?? 0),
                'payload_sample' => is_array($decoded['payload'] ?? null) ? json_encode($decoded['payload']) : ($decoded['payload'] ?? null),
                'reasons' => $decoded['reasons'] ?? null,
                'banned_at' => $decoded['banned_at'] ?? null,
                'expires_at' => $decoded['expires_at'] ?? null,
                'lifted_by' => $decoded['lifted_by'] ?? null,
                'user_agent' => $decoded['user_agent'] ?? null,
                'occurred_at' => $decoded['timestamp'] ?? $fallbackNow,
            ];
        }

        return $batch;
    }
}
