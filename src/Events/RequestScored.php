<?php

namespace AppGuard\Events;

use AppGuard\Core\Decision;
use AppGuard\Core\RequestContext;
use Illuminate\Foundation\Events\Dispatchable;

final class RequestScored
{
    use Dispatchable;

    public function __construct(
        public readonly RequestContext $context,
        public readonly Decision $decision,
    ) {
    }
}

