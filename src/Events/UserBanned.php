<?php

namespace AppGuard\Events;

use AppGuard\Core\RequestContext;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

final class UserBanned
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly mixed $user,
        public readonly int $score,
        public readonly string $reason,
        public readonly ?RequestContext $context = null,
        public readonly int $bannedAt = 0,
        public readonly ?int $expiresAt = null,
        public readonly ?string $detector = null,
        public readonly ?string $tenant = null,
    ) {
    }
}
