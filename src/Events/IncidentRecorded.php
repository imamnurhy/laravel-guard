<?php

namespace AppGuard\Events;

use Illuminate\Foundation\Events\Dispatchable;

final class IncidentRecorded
{
    use Dispatchable;

    /** @param array<string, mixed> $incident */
    public function __construct(
        public readonly array $incident,
    ) {
    }
}

