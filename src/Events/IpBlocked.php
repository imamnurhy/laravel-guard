<?php

namespace AppGuard\Events;

use AppGuard\Core\BanRecord;
use Illuminate\Foundation\Events\Dispatchable;

final class IpBlocked
{
    use Dispatchable;

    public function __construct(
        public readonly string $ip,
        public readonly int $seconds,
        public readonly string $reason = 'Manual IP block',
        public readonly string $source = 'manual',
        public readonly int $score = 100,
        public readonly ?BanRecord $record = null,
        public readonly ?string $tenant = null,
    ) {
    }
}

