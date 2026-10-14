<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;
use AppGuard\Core\Support\PathMatcher;

/**
 * Jebakan: path yang tidak mungkin diakses user asli (/.env, /wp-admin) dan
 * field form tersembunyi yang hanya diisi bot.
 */
final class HoneypotDetector extends AbstractDetector
{
    public function __construct(private array $config = [])
    {
    }

    public function name(): string
    {
        return 'honeypot';
    }

    public function inspect(RequestContext $ctx): array
    {
        $score = (int) ($this->config['score'] ?? 100);

        if ($hit = PathMatcher::matches($this->config['paths'] ?? [], $ctx->path)) {
            return [new Signal($this->name(), $score, "trap path '{$hit}'", persist: true)];
        }

        $filled = $ctx->attributes['honeypot_fields'] ?? [];
        if ($filled !== []) {
            return [new Signal($this->name(), $score, 'trap field filled: ' . implode(',', $filled), persist: true)];
        }

        return [];
    }
}
