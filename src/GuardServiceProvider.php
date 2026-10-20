<?php

namespace AppGuard;

use AppGuard\Core\Contracts\BanRegistry;
use AppGuard\Core\Contracts\Store;
use AppGuard\Core\Contracts\VulnerabilityStore;
use AppGuard\Core\Detectors\AnomalyDetector;
use AppGuard\Core\Detectors\BruteForceDetector;
use AppGuard\Core\Detectors\DeniedAccessDetector;
use AppGuard\Core\Detectors\HoneypotDetector;
use AppGuard\Core\Detectors\MaliciousPayloadDetector;
use AppGuard\Core\Detectors\ParameterTamperingDetector;
use AppGuard\Core\Detectors\PathTraversalDetector;
use AppGuard\Core\Guard;
use AppGuard\Console\BanCommand;
use AppGuard\Console\BlockCommand;
use AppGuard\Console\DoctorCommand;
use AppGuard\Console\HeartbeatCommand;
use AppGuard\Console\InstallCommand;
use AppGuard\Console\ShipTelemetryCommand;
use AppGuard\Console\StatusCommand;
use AppGuard\Console\SyncCommand;
use AppGuard\Console\TestRuleCommand;
use AppGuard\Console\UnblockCommand;
use AppGuard\Console\UnbanUserCommand;
use AppGuard\Console\UserStatusCommand;
use AppGuard\Console\BanUserCommand;
use AppGuard\Core\ControlPlaneClient;
use AppGuard\Core\Stores\ArrayBanRegistry;
use AppGuard\Core\Stores\ArrayStore;
use AppGuard\Core\Stores\ArrayVulnerabilityStore;
use AppGuard\Core\Stores\NullVulnerabilityStore;
use AppGuard\Events\BanLifted;
use AppGuard\Events\IncidentRecorded;
use AppGuard\Events\IpBlocked;
use AppGuard\Events\RequestScored;
use AppGuard\Handlers\DefaultUserBanHandler;
use AppGuard\Http\GuardMiddleware;
use AppGuard\Listeners\AuthEventListener;
use AppGuard\Stores\CacheBanRegistry;
use AppGuard\Stores\CacheStore;
use AppGuard\Stores\JsonFileVulnerabilityStore;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\ServiceProvider;

class GuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/guard.php', 'guard');

        $this->app->singleton(Store::class, function ($app) {
            $storeName = $app['config']->get('guard.store');
            $prefix = $this->resolveKeyPrefix($app['config']->get('guard', []));
            if ($storeName === 'array') {
                return new ArrayStore();
            }

            return new CacheStore($app['cache']->store($storeName), $prefix);
        });

        $this->app->singleton(BanRegistry::class, function ($app) {
            $storeName = $app['config']->get('guard.store');
            $prefix = $this->resolveKeyPrefix($app['config']->get('guard', []));
            if ($storeName === 'array') {
                return new ArrayBanRegistry();
            }

            return new CacheBanRegistry($app['cache']->store($storeName), "{$prefix}bans:index");
        });

        $this->app->singleton(VulnerabilityStore::class, function ($app) {
            $driver = $app['config']->get('guard.vulnerability.driver', 'jsonl');

            return match ($driver) {
                'null', 'none', false => new NullVulnerabilityStore(),
                'array', 'memory' => new ArrayVulnerabilityStore(),
                default => new JsonFileVulnerabilityStore(
                    $app['config']->get('guard.vulnerability.dataset_path', storage_path('app/guard/vulnerabilities.jsonl'))
                ),
            };
        });

        $this->app->singleton(DefaultUserBanHandler::class, fn ($app) => new DefaultUserBanHandler(
            $app->make(VulnerabilityStore::class),
            $app->make(BanRegistry::class),
        ));

        $this->app->singleton(BruteForceDetector::class, fn ($app) => new BruteForceDetector(
            $app->make(Store::class),
            $app['config']->get('guard.detectors.brute_force', []),
        ));

        $this->app->singleton(RequestContextFactory::class, fn ($app) => new RequestContextFactory(
            $app['config']->get('guard'),
        ));

        $this->app->singleton(\AppGuard\Core\Contracts\DynamicRuleStore::class, fn ($app) => new \AppGuard\Stores\CacheDynamicRuleStore(
            $app['cache']->store($app['config']->get('guard.store')),
            $app['config']->get('guard.control_plane.app_key')
        ));

        $this->app->singleton(ControlPlaneClient::class, fn ($app) => new ControlPlaneClient());

        $this->app->singleton(Guard::class, function ($app) {
            $cfg = $app['config']->get('guard');
            $store = $app->make(Store::class);
            $vulnStore = $app->make(VulnerabilityStore::class);
            $ruleStore = $app->make(\AppGuard\Core\Contracts\DynamicRuleStore::class);

            // Terapkan Kebijakan Keamanan (Remote Policy) jika ada
            if ($policy = $ruleStore->getPolicy()) {
                if (isset($policy['enabled'])) {
                    $cfg['enabled'] = (bool) $policy['enabled'];
                }
                if (isset($policy['mode'])) {
                    $cfg['mode'] = (string) $policy['mode'];
                }
                if (isset($policy['fail_open'])) {
                    $cfg['fail_open'] = (bool) $policy['fail_open'];
                }
                if (isset($policy['throttle_threshold'])) {
                    $cfg['thresholds']['throttle'] = (int) $policy['throttle_threshold'];
                }
                if (isset($policy['block_threshold'])) {
                    $cfg['thresholds']['block'] = (int) $policy['block_threshold'];
                }
                if (isset($policy['user_ban']['enabled'])) {
                    $cfg['user_ban']['enabled'] = (bool) $policy['user_ban']['enabled'];
                }
                if (isset($policy['user_ban']['threshold'])) {
                    $cfg['user_ban']['threshold'] = (int) $policy['user_ban']['threshold'];
                }
            }

            // Gabungkan Dynamic Honeypots dari Control Plane
            if (! empty($dynHoneypots = $ruleStore->getDynamicHoneypots())) {
                $staticPaths = $cfg['detectors']['honeypot']['paths'] ?? [];
                $cfg['detectors']['honeypot']['paths'] = array_values(array_unique(array_merge($staticPaths, $dynHoneypots)));
            }

            $detectors = [];

            // 1. Honeypot Detector
            if ($cfg['detectors']['honeypot']['enabled'] ?? false) {
                $detectors[] = new HoneypotDetector($cfg['detectors']['honeypot']);
            }

            // 2. Brute Force Detector
            if ($cfg['detectors']['brute_force']['enabled'] ?? false) {
                $detectors[] = $app->make(BruteForceDetector::class);
            }

            // 3. Denied Access / Probing Detector
            if ($cfg['detectors']['denied_access']['enabled'] ?? false) {
                $detectors[] = new DeniedAccessDetector($store, $cfg['detectors']['denied_access']);
            }

            // 4. Path Traversal Detector
            if ($cfg['detectors']['path_traversal']['enabled'] ?? false) {
                $detectors[] = new PathTraversalDetector($cfg['detectors']['path_traversal']);
            }

            // 5. Malicious Payload (SQLi & XSS) Detector
            if ($cfg['detectors']['malicious_payload']['enabled'] ?? false) {
                $detectors[] = new MaliciousPayloadDetector($cfg['detectors']['malicious_payload']);
            }

            // 6. Parameter Tampering Detector
            if ($cfg['detectors']['parameter_tampering']['enabled'] ?? false) {
                $detectors[] = new ParameterTamperingDetector($cfg['detectors']['parameter_tampering']);
            }

            // 7. Adaptive Anomaly & Fuzzing Detector
            if ($cfg['detectors']['anomaly']['enabled'] ?? false) {
                $detectors[] = new AnomalyDetector($store, $cfg['detectors']['anomaly']);
            }

            // 8. Guard Sensor Token Integrity Detector (Client Security Verification)
            if ($cfg['detectors']['sensor_token']['enabled'] ?? true) {
                $detectors[] = new \AppGuard\Core\Detectors\SensorTokenDetector(array_merge(
                    $cfg['detectors']['sensor_token'] ?? [],
                    ['secret_hash' => $cfg['control_plane']['app_secret'] ?? '']
                ));
            }

            // Custom user detectors
            foreach ($cfg['custom_detectors'] ?? [] as $class) {
                $detectors[] = $app->make($class);
            }

            $guard = new Guard(
                $store,
                $detectors,
                $cfg,
                $app['log']->channel($cfg['log_channel'] ?? null),
                $vulnStore,
                $app->make(BanRegistry::class),
            );

            // Hook callback user banned, force logout, dan Laravel Events
            $banHandler = $app->make(DefaultUserBanHandler::class);
            $guard->setOnUserBanned(function ($user, $score, $reason, $ctx) use ($banHandler) {
                $banHandler->ban($user, $score, $reason, $ctx);
            });
            $guard->setOnUserForceLoggedOut(function ($user, $score, $reason, $ctx) use ($banHandler) {
                $banHandler->handleForceLogout($user, $score, $reason, $ctx);
            });
            $guard->onBan(function ($ban) use ($guard) {
                if ($ban->type === \AppGuard\Core\BanRecord::TYPE_IP) {
                    event(new IpBlocked(
                        ip: $ban->subject,
                        seconds: $ban->remaining() ?? 0,
                        reason: $ban->reason,
                        source: $ban->source,
                        score: $ban->score,
                        record: $ban,
                        tenant: $guard->currentTenant(),
                    ));
                }
            });
            $guard->onBanLifted(function ($type, $subject, $liftedBy, $reason, $previous) use ($guard) {
                event(new BanLifted($type, $subject, $liftedBy, $reason, $previous, $guard->currentTenant()));
            });
            $guard->onIncident(function (array $incident) {
                event(new IncidentRecorded($incident));
            });
            $guard->onScored(function ($ctx, $decision) {
                if ($decision->signals !== [] || ! $decision->isAllowed()) {
                    event(new RequestScored($ctx, $decision));
                }
            });

            return $guard;
        });

        $this->app->singleton(GuardMiddleware::class);
    }

    private function resolveKeyPrefix(array $cfg): string
    {
        $base = rtrim((string) ($cfg['key_prefix'] ?? 'guard'), ':');
        $tenant = (string) ($cfg['tenant_id'] ?? $cfg['control_plane']['app_key'] ?? '');

        return $tenant !== '' && ! empty($cfg['prefix_by_tenant'])
            ? "{$base}:{$tenant}:"
            : "{$base}:";
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/guard.php' => config_path('guard.php'),
        ], 'guard-config');

        if (! config('guard.enabled', true)) {
            return;
        }

        // Event auth Laravel -> counter brute force
        $events = $this->app['events'];
        $listener = fn () => new AuthEventListener(
            $this->app->make(BruteForceDetector::class),
            $this->app->make(RequestContextFactory::class),
            $this->app['config']->get('guard'),
        );
        $events->listen(Failed::class, fn (Failed $e) => $listener()->onFailed($e));
        $events->listen(Login::class, fn (Login $e) => $listener()->onLogin($e));

        // Daftarkan route middleware alias 'guard'
        if (isset($this->app['router'])) {
            $this->app['router']->aliasMiddleware('guard', GuardMiddleware::class);

            // Route Receiver Webhook Instan (Tanpa CSRF)
            $this->app['router']->post('/guard/webhook', [\AppGuard\Http\WebhookController::class, 'handle'])
                ->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class, \Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class]);

            // Route Internal Proxy untuk Sensor Script & Beacon (Menyembunyikan Private IP Control Plane)
            $this->app['router']->get('/guard/sensor.js', [\AppGuard\Http\SensorProxyController::class, 'script']);
            $this->app['router']->post('/guard/beacon', [\AppGuard\Http\SensorProxyController::class, 'beacon'])
                ->withoutMiddleware([\App\Http\Middleware\VerifyCsrfToken::class, \Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class]);
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallCommand::class,
                BanCommand::class,
                BlockCommand::class,
                UnblockCommand::class,
                StatusCommand::class,
                DoctorCommand::class,
                TestRuleCommand::class,
                SyncCommand::class,
                ShipTelemetryCommand::class,
                HeartbeatCommand::class,
                UnbanUserCommand::class,
                UserStatusCommand::class,
                BanUserCommand::class,
            ]);
        }
    }
}
