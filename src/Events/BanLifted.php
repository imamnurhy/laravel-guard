<?php

namespace AppGuard\Events;

use AppGuard\Core\BanRecord;
use Illuminate\Foundation\Events\Dispatchable;

final class BanLifted
{
    use Dispatchable;

    public function __construct(
        public readonly string $type,
        public readonly string $subject,
        public readonly string $liftedBy = 'system',
        public readonly string $reason = '',
        public readonly ?BanRecord $previous = null,
        public readonly ?string $tenant = null,
    ) {
    }
}

