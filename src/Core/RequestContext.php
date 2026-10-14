<?php

namespace AppGuard\Core;

/** Request yang sudah dinormalisasi. Core tidak tahu apa pun soal Laravel. */
final class RequestContext
{
    public function __construct(
        public readonly string $ip,
        public readonly string $method,
        public readonly string $path,
        public readonly string $userAgent = '',
        public readonly ?string $routeName = null,
        public readonly ?string $userId = null,
        public readonly ?string $identifier = null,
        public readonly array $attributes = [],
    ) {
    }
}
