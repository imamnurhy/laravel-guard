<?php

namespace AppGuard\Stores;

use AppGuard\Core\Contracts\DynamicRuleStore;
use Illuminate\Contracts\Cache\Repository as CacheRepository;

class CacheDynamicRuleStore implements DynamicRuleStore
{
    private string $appKey;

    public function __construct(
        private CacheRepository $cache,
        ?string $appKey = null
    ) {
        $this->appKey = $appKey ?: (string) config('guard.control_plane.app_key', 'default');
    }

    private function key(string $suffix): string
    {
        return "guard:{$this->appKey}:{$suffix}";
    }

    public function addDynamicHoneypots(array $paths): void
    {
        try {
            $existing = $this->getDynamicHoneypots();
            $merged = array_values(array_unique(array_merge($existing, $paths)));
            $this->cache->put($this->key('honeypots'), $merged, 86400 * 7);
        } catch (\Throwable $e) {
            // Fail-open
        }
    }

    public function getDynamicHoneypots(): array
    {
        try {
            return (array) $this->cache->get($this->key('honeypots'), []);
        } catch (\Throwable $e) {
            return [];
        }
    }

    public function setDynamicThresholds(array $thresholds): void
    {
        try {
            $this->cache->put($this->key('thresholds'), $thresholds, 86400 * 7);
        } catch (\Throwable $e) {
            // Fail-open
        }
    }

    public function getDynamicThresholds(): array
    {
        try {
            return (array) $this->cache->get($this->key('thresholds'), []);
        } catch (\Throwable $e) {
            return [];
        }
    }

    public function setPolicy(array $policy): void
    {
        try {
            $this->cache->put($this->key('policy'), $policy, 86400 * 7);
        } catch (\Throwable $e) {
            // Fail-open
        }
    }

    public function getPolicy(): ?array
    {
        try {
            return $this->cache->get($this->key('policy'));
        } catch (\Throwable $e) {
            return null;
        }
    }
}
