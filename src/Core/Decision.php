<?php

namespace AppGuard\Core;

final class Decision
{
    /** @param Signal[] $signals */
    public function __construct(
        public readonly Action $action,
        public readonly int $score = 0,
        public readonly array $signals = [],
        public readonly int $retryAfter = 0,
    ) {
    }

    public static function allow(): self
    {
        return new self(Action::Allow);
    }

    public function isAllowed(): bool
    {
        return $this->action === Action::Allow;
    }

    /** @return string[] */
    public function reasons(): array
    {
        return array_map(fn (Signal $s) => "{$s->detector}: {$s->reason}", $this->signals);
    }
}
