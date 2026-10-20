<?php

namespace AppGuard\Console;

use AppGuard\Core\ControlPlaneClient;
use Illuminate\Console\Command;

final class ShipTelemetryCommand extends Command
{
    protected $signature = 'guard:ship-telemetry {--batch-size=100 : Jumlah baris per batch pengiriman}';
    protected $description = 'Kirim batch rekaman insiden dari buffer lokal (vulnerabilities.jsonl) ke Centralized Control Plane';

    public function handle(ControlPlaneClient $client): int
    {
        $filePath = config('guard.vulnerability.dataset_path', storage_path('app/guard/vulnerabilities.jsonl'));

        if (! file_exists($filePath) || filesize($filePath) === 0) {
            $this->info('Buffer insiden kosong. Tidak ada data yang dikirim.');
            return self::SUCCESS;
        }

        if (! $client->isConfigured()) {
            $this->warn('Konfigurasi Control Plane belum lengkap. Pengiriman buffer ditunda.');
            return self::SUCCESS;
        }

        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (empty($lines)) {
            return self::SUCCESS;
        }

        $batchSize = (int) $this->option('batch-size');
        $chunk = array_slice($lines, 0, $batchSize);
        $batch = [];

        foreach ($chunk as $line) {
            $decoded = json_decode($line, true);
            if (is_array($decoded)) {
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
                    'occurred_at' => $decoded['timestamp'] ?? now()->toIso8601String(),
                ];
            }
        }

        if (empty($batch)) {
            return self::SUCCESS;
        }

        $rawBody = json_encode(['batch' => $batch]);

        try {
            $response = $client->request('POST', '/telemetry/ingest', [
                'headers' => ['Content-Type' => 'application/json'],
                'body' => $rawBody,
            ]);

            if ($response->successful()) {
                // Hapus baris yang berhasil dikirim dari buffer
                $remaining = array_slice($lines, count($chunk));
                if (empty($remaining)) {
                    file_put_contents($filePath, '');
                } else {
                    file_put_contents($filePath, implode("\n", $remaining) . "\n");
                }

                $this->info('✓ Berhasil mengirim ' . count($batch) . ' rekaman telemetri ke Control Plane.');
                return self::SUCCESS;
            }

            $this->warn("Gagal mengirim telemetri. Status {$response->status()}: " . $response->body());
            return self::FAILURE;
        } catch (\Throwable $e) {
            $this->warn('Gagal menghubungi Control Plane: ' . $e->getMessage() . '. Data aman tersimpan di buffer lokal.');
            return self::SUCCESS;
        }
    }
}
