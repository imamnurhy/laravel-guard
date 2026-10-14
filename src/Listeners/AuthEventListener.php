<?php

namespace AppGuard\Listeners;

use AppGuard\Core\Detectors\BruteForceDetector;
use AppGuard\RequestContextFactory;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;

final class AuthEventListener
{
    public function __construct(
        private BruteForceDetector $bruteForce,
        private RequestContextFactory $factory,
        private array $config,
    ) {
    }

    public function onFailed(Failed $event): void
    {
        $request = request();
        $identifier = null;

        foreach ($this->config['identifier_keys'] ?? [] as $key) {
            if (isset($event->credentials[$key]) && is_string($event->credentials[$key])) {
                $identifier = $event->credentials[$key];
                break;
            }
        }

        $this->bruteForce->recordFailure((string) $request->ip(), $identifier ?? $this->factory->identifier($request));
    }

    public function onLogin(Login $event): void
    {
        $request = request();

        $this->bruteForce->recordSuccess((string) $request->ip(), $this->factory->identifier($request));
    }
}
