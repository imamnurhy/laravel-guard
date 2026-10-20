<?php

namespace AppGuard\Console;

use AppGuard\Core\Contracts\DynamicRuleStore;
use AppGuard\Core\ControlPlaneClient;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;

final class SyncCommand extends Command
{
    protected $signature = 'guard:sync {--force : Abaikan cache ETag dan paksa sinkronisasi ulang}';
    protected $description = 'Sinkronisasi aturan dinamis dan IP blacklist dari Centralized WAF Control Plane ke cache lokal';

    public function handle(DynamicRuleStore $ruleStore, ControlPlaneClient $client): int
    {
        if (! $client->isConfigured()) {
            $this->warn('Konfigurasi Control Plane belum lengkap (GUARD_URL, GUARD_KEY, GUARD_SECRET). Sinkronisasi dilewati.');
            return self::SUCCESS;
        }

        $appKey = $client->getAppKey();
        $etagCacheKey = "guard:sync:etag:{$appKey}";
        $cachedEtag = $this->option('force') ? null : Cache::get($etagCacheKey);

        $cbKey = "guard:circuit_breaker:{$appKey}:failures";
        $cbOpenedUntilKey = "guard:circuit_breaker:{$appKey}:opened_until";
        $openedUntil = Cache::get($cbOpenedUntilKey);

        if ($openedUntil && now()->timestamp < $openedUntil && ! $this->option('force')) {
            $this->warn('⚡ Circuit Breaker AKTIF: Control Plane sedang mengalami gangguan. Menggunakan snapshot rule lokal terakhir (Fail-Open).');
            $this->loadFallbackSnapshot($ruleStore, $appKey);
            return self::SUCCESS;
        }

        $headers = [];
        if ($cachedEtag) {
            $headers['If-None-Match'] = $cachedEtag;
        }

        try {
            $response = $client->request('GET', '/rules/sync', [
                'headers' => $headers,
            ]);

            if ($response->status() === 304) {
                Cache::forget($cbKey);
                $this->info('✓ Dynamic rules sudah up-to-date (HTTP 304 Not Modified).');
                return self::SUCCESS;
            }

            if ($response->successful()) {
                $data = $response->json();

                // Reset Circuit Breaker setelah berhasil
                Cache::forget($cbKey);
                Cache::forget($cbOpenedUntilKey);

                // 1. Simpan Dynamic Honeypots
                if (! empty($data['honeypots']) && is_array($data['honeypots'])) {
                    $ruleStore->addDynamicHoneypots($data['honeypots']);
                    $this->info('✓ Disinkronkan ' . count($data['honeypots']) . ' honeypot paths.');
                }

                // 2. Simpan Dynamic Thresholds
                if (! empty($data['thresholds']) && is_array($data['thresholds'])) {
                    $ruleStore->setDynamicThresholds($data['thresholds']);
                    $this->info('✓ Disinkronkan dynamic thresholds.');
                }

                // 3. Simpan IP Blacklist ke Cache Lokal Tenant
                if (! empty($data['banned_ips']) && is_array($data['banned_ips'])) {
                    $bannedKey = "guard:{$appKey}:banned_ips";
                    Cache::put($bannedKey, $data['banned_ips'], 86400);
                    $this->info('✓ Disinkronkan ' . count($data['banned_ips']) . ' banned IPs.');
                }

                // 4. Simpan Centralized Policy jika ada
                if (! empty($data['policy']) && is_array($data['policy'])) {
                    $ruleStore->setPolicy($data['policy']);
                    $this->info('✓ Disinkronkan remote policy v' . ($data['policy']['version'] ?? '1') . ' (mode: ' . ($data['policy']['mode'] ?? 'enforce') . ').');
                }

                // 4b. Eksekusi antrean perintah ban/unban dari Control Plane (pull queue)
                if (! empty($data['commands']) && is_array($data['commands']) && app()->bound(\AppGuard\Core\Guard::class)) {
                    $guard = app(\AppGuard\Core\Guard::class);
                    $banHandler = app()->bound(\AppGuard\Handlers\DefaultUserBanHandler::class)
                        ? app(\AppGuard\Handlers\DefaultUserBanHandler::class)
                        : null;
                    $ackIds = [];
                    foreach ($data['commands'] as $cmd) {
                        if (! is_array($cmd)) {
                            continue;
                        }
                        $action = (string) ($cmd['action'] ?? $cmd['event'] ?? '');
                        $subject = (string) ($cmd['subject'] ?? $cmd['ip'] ?? $cmd['user_id'] ?? '');
                        if ($subject === '') {
                            continue;
                        }
                        if ($action === 'unban_ip' || $action === 'unblock') {
                            $guard->unblock($subject, 'control_plane', (string) ($cmd['reason'] ?? 'Control Plane Unban'));
                            if (! empty($cmd['id'])) {
                                $ackIds[] = $cmd['id'];
                            }
                        } elseif ($action === 'unban_user') {
                            $guard->unbanUser($subject, 'control_plane', (string) ($cmd['reason'] ?? 'Control Plane Unban'));
                            $banHandler?->unban($subject, syncDb: (bool) ($cmd['sync_db'] ?? true));
                            if (! empty($cmd['id'])) {
                                $ackIds[] = $cmd['id'];
                            }
                        } elseif ($action === 'ban_ip' || $action === 'block') {
                            $guard->block($subject, (int) ($cmd['ttl'] ?? 3600), (string) ($cmd['reason'] ?? 'Control Plane Ban'), 'control_plane');
                            if (! empty($cmd['id'])) {
                                $ackIds[] = $cmd['id'];
                            }
                        }
                    }
                    if ($ackIds !== []) {
                        try {
                            $client->request('POST', '/commands/ack', [
                                'headers' => ['Content-Type' => 'application/json'],
                                'body' => (string) json_encode(['ids' => $ackIds]),
                            ]);
                        } catch (\Throwable) {
                            // Fail-open
                        }
                        $this->info('✓ Diterapkan ' . count($ackIds) . ' perintah ban/unban dari Control Plane.');
                    }
                }

                // 5. Simpan Snapshot Cadangan Lokal "Last Known Good Rules & Policy"
                $this->saveFallbackSnapshot($appKey, $data);

                // Simpan ETag baru
                $newEtag = $response->header('ETag');
                if ($newEtag) {
                    Cache::put($etagCacheKey, $newEtag, 86400);
                }

                $this->info('✓ Sinkronisasi rules dari Control Plane sukses.');
                return self::SUCCESS;
            }

            $this->warn("Control plane merespons dengan status {$response->status()}: " . $response->body());
            $this->recordFailure($appKey, $cbKey, $cbOpenedUntilKey);
            $this->loadFallbackSnapshot($ruleStore, $appKey);
            return self::FAILURE;
        } catch (\Throwable $e) {
            // Fail-open: Jangan throw error fatal ke caller
            $this->warn("Fail-open: Gagal menghubungi Control Plane ({$e->getMessage()}). Menggunakan aturan lokal yang ada.");
            $this->recordFailure($appKey, $cbKey, $cbOpenedUntilKey);
            $this->loadFallbackSnapshot($ruleStore, $appKey);
            return self::SUCCESS;
        }
    }

    private function recordFailure(string $appKey, string $cbKey, string $cbOpenedUntilKey): void
    {
        $failures = (int) Cache::increment($cbKey);
        if ($failures >= 3) {
            Cache::put($cbOpenedUntilKey, now()->addMinutes(5)->timestamp, 300);
            $this->error("⚡ Circuit Breaker DIBUKA untuk 5 menit ke depan setelah {$failures}x kegagalan koneksi beruntun.");
        }
    }

    private function saveFallbackSnapshot(string $appKey, array $data): void
    {
        try {
            $path = storage_path("app/guard/snapshot_{$appKey}.json");
            $dir = dirname($path);
            if (! is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
            file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT));
        } catch (\Throwable $e) {
            // Fail-open silent
        }
    }

    private function loadFallbackSnapshot(DynamicRuleStore $ruleStore, string $appKey): void
    {
        $path = storage_path("app/guard/snapshot_{$appKey}.json");
        if (! file_exists($path)) {
            return;
        }

        try {
            $data = json_decode(file_get_contents($path), true);
            if (! empty($data['honeypots']) && is_array($data['honeypots'])) {
                $ruleStore->addDynamicHoneypots($data['honeypots']);
            }
            if (! empty($data['thresholds']) && is_array($data['thresholds'])) {
                $ruleStore->setDynamicThresholds($data['thresholds']);
            }
            if (! empty($data['banned_ips']) && is_array($data['banned_ips'])) {
                Cache::put("guard:{$appKey}:banned_ips", $data['banned_ips'], 86400);
            }
            if (! empty($data['policy']) && is_array($data['policy'])) {
                $ruleStore->setPolicy($data['policy']);
            }
            $this->info("✓ Memuat cadangan 'Last Known Good Rules' dari snapshot lokal.");
        } catch (\Throwable $e) {
            // Fail-open silent
        }
    }
}
