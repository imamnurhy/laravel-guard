<?php

namespace AppGuard\Facades;

use AppGuard\Core\Guard;
use Illuminate\Support\Facades\Facade;

/**
 * @method static bool enabled()
 * @method static bool enforcing()
 * @method static \AppGuard\Core\Decision inspect(\AppGuard\Core\RequestContext $ctx)
 * @method static void observe(\AppGuard\Core\RequestContext $ctx, int $status)
 * @method static bool recordViolation(mixed $user, string $ruleKey, ?int $points = null, ?string $reason = null, ?\AppGuard\Core\RequestContext $ctx = null)
 * @method static void recordVulnerability(array $incident)
 * @method static void block(string $ip, int $seconds)
 * @method static void unblock(string $ip)
 * @method static bool isBlocked(string $ip)
 * @method static int scoreOf(string $ip)
 * @method static int scoreOfUser(string|int $userId)
 *
 * @see \AppGuard\Core\Guard
 */
class SecurityGuard extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return Guard::class;
    }
}
