<?php

namespace AppGuard;

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
use AppGuard\Console\BlockCommand;
use AppGuard\Console\InstallCommand;
use AppGuard\Console\StatusCommand;
use AppGuard\Console\UnblockCommand;
use AppGuard\Handlers\DefaultUserBanHandler;
use AppGuard\Http\GuardMiddleware;
use AppGuard\Listeners\AuthEventListener;
use AppGuard\Notifications\TebotNotifier;
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

        $this->app->singleton(Store::class, fn ($app) => new CacheStore(
            $app['cache']->store($app['config']->get('guard.store')),
        ));

        $this->app->singleton(VulnerabilityStore::class, fn ($app) => new JsonFileVulnerabilityStore(
            $app['config']->get('guard.vulnerability.dataset_path', storage_path('app/guard/vulnerabilities.jsonl'))
        ));

        $this->app->singleton(TebotNotifier::class);
        $this->app->singleton(DefaultUserBanHandler::class);

        $this->app->singleton(BruteForceDetector::class, fn ($app) => new BruteForceDetector(
            $app->make(Store::class),
            $app['config']->get('guard.detectors.brute_force', []),
        ));

        $this->app->singleton(RequestContextFactory::class, fn ($app) => new RequestContextFactory(
            $app['config']->get('guard'),
        ));

        $this->app->singleton(Guard::class, function ($app) {
            $cfg = $app['config']->get('guard');
            $store = $app->make(Store::class);
            $vulnStore = $app->make(VulnerabilityStore::class);
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

            // Custom user detectors
            foreach ($cfg['custom_detectors'] ?? [] as $class) {
                $detectors[] = $app->make($class);
            }

            $guard = new Guard(
                $store,
                $detectors,
                $cfg,
                $app['log']->channel($cfg['log_channel'] ?? null),
                $vulnStore
            );

            // Hook callback user banned ke BanHandler
            $banHandler = $app->make(DefaultUserBanHandler::class);
            $guard->setOnUserBanned(function ($user, $score, $reason, $ctx) use ($banHandler) {
                $banHandler->ban($user, $score, $reason, $ctx);
            });

            return $guard;
        });

        $this->app->singleton(GuardMiddleware::class);
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
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallCommand::class,
                BlockCommand::class,
                UnblockCommand::class,
                StatusCommand::class,
            ]);
        }
    }
}
