<?php

namespace AppGuard\Console;

use AppGuard\Core\ControlPlaneClient;
use Illuminate\Console\Command;

final class HeartbeatCommand extends Command
{
    protected $signature = 'guard:heartbeat';
    protected $description = 'Kirim sinyal heartbeat kesehatan enforcer ke Centralized Control Plane';

    public function handle(ControlPlaneClient $client): int
    {
        if (! $client->isConfigured()) {
            $this->warn('Konfigurasi Control Plane belum lengkap (GUARD_URL, GUARD_KEY, GUARD_SECRET). Heartbeat dilewati.');
            return self::SUCCESS;
        }

        $body = json_encode([
            'enforcer_version' => '1.0.0',
            'environment' => config('app.env', 'production'),
            'guard_mode' => config('guard.mode', 'monitor'),
            'php_version' => PHP_VERSION,
            'laravel_version' => app()->version(),
        ]);

        try {
            $response = $client->request('POST', '/heartbeat', [
                'headers' => ['Content-Type' => 'application/json'],
                'body' => $body,
            ]);

            if ($response->successful()) {
                $data = $response->json();
                $this->info("✓ Heartbeat terhubung ke Control Plane (App ID: {$data['app_id']}, Status: " . ($data['is_active'] ? 'Active' : 'Inactive') . ").");
                return self::SUCCESS;
            }

            $this->warn("Heartbeat gagal dengan status {$response->status()}: " . $response->body());
            return self::FAILURE;
        } catch (\Throwable $e) {
            $this->warn('Gagal mengirim heartbeat ke Control Plane: ' . $e->getMessage());
            return self::SUCCESS;
        }
    }
}
