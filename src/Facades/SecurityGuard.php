<?php

namespace AppGuard\Facades;

use AppGuard\Core\Guard;
use Illuminate\Support\Facades\Facade;

/**
 * @method static bool enabled()
 * @method static bool enforcing()
 * @method static \AppGuard\Core\Decision inspect(\AppGuard\Core\RequestContext $ctx, array $overrides = [])
 * @method static void observe(\AppGuard\Core\RequestContext $ctx, int $status)
 * @method static bool recordViolation(mixed $user, string $ruleKey, ?int $points = null, ?string $reason = null, ?\AppGuard\Core\RequestContext $ctx = null)
 * @method static void recordVulnerability(array $incident)
 * @method static void block(string $ip, int $seconds, string $reason = 'Manual IP block', string $source = 'manual', int $score = 100)
 * @method static void unblock(string $ip, string $liftedBy = 'system', string $reason = 'Manual unblock')
 * @method static bool isBlocked(string $ip)
 * @method static int scoreOf(string $ip)
 * @method static int scoreOfUser(string|int $userId)
 * @method static void unbanUser(string|int $userId, string $liftedBy = 'system', string $reason = 'Manual unban')
 * @method static bool isUserBanned(string|int $userId)
 * @method static bool isUserForceLoggedOut(string|int $userId)
 * @method static array<string, \AppGuard\Core\BanRecord> bans(?string $type = null)
 * @method static ?\AppGuard\Core\BanRecord findBan(string $type, string|int $subject)
 * @method static int clearBans(?string $type = null, string $liftedBy = 'system', string $reason = 'Bulk clear')
 * @method static ?\AppGuard\Core\Contracts\BanRegistry banRegistry()
 * @method static ?\AppGuard\Core\Contracts\VulnerabilityStore vulnerabilityStore()
 * @method static \AppGuard\Core\Guard addDetector(\AppGuard\Core\Contracts\Detector $detector)
 * @method static \AppGuard\Core\Guard onBan(?callable $callback)
 * @method static \AppGuard\Core\Guard onBanLifted(?callable $callback)
 * @method static \AppGuard\Core\Guard onIncident(?callable $callback)
 * @method static \AppGuard\Core\Guard onScored(?callable $callback)
 * @method static \AppGuard\Core\Guard respondUsing(?callable $callback)
 * @method static \AppGuard\Core\Guard resolveUserUsing(?callable $resolver)
 * @method static \AppGuard\Core\Guard resolveTenantUsing(?callable $resolver)
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
