<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\Contracts\Store;
use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;
use AppGuard\Core\Support\PathMatcher;

/**
 * Enumeration / probing: banyak 403 (policy) dan 404 (ModelNotFound) dalam waktu singkat.
 * Hanya bisa diketahui di fase POST, hasilnya masuk ke reputasi dan berlaku di request berikutnya.
 */
final class DeniedAccessDetector extends AbstractDetector
{
    public function __construct(private Store $store, private array $config = [])
    {
    }

    public function name(): string
    {
        return 'denied_access';
    }

    public function observe(RequestContext $ctx, int $status): array
    {
        if (! in_array($status, $this->config['statuses'] ?? [403, 404], true)) {
            return [];
        }

        if (PathMatcher::matches($this->config['ignore_paths'] ?? [], $ctx->path) !== null) {
            return [];
        }

        $subject = $ctx->userId !== null ? "u:{$ctx->userId}" : "ip:{$ctx->ip}";
        $count = $this->store->hit("deny:{$subject}", (int) ($this->config['window'] ?? 60));

        if ($count >= ($this->config['threshold'] ?? 15)) {
            return [new Signal(
                $this->name(),
                (int) ($this->config['score'] ?? 40),
                "{$count} denied/not-found responses within window",
                persist: true,
            )];
        }

        return [];
    }
}
