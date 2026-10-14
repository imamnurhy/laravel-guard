<?php

namespace AppGuard\Core\Contracts;

use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

interface Detector
{
    public function name(): string;

    /**
     * Fase PRE: sebelum request diproses aplikasi. Harus murah (hanya baca counter).
     *
     * @return Signal[]
     */
    public function inspect(RequestContext $ctx): array;

    /**
     * Fase POST: setelah response dibuat (route, user, dan hasil otorisasi sudah diketahui).
     *
     * @return Signal[]
     */
    public function observe(RequestContext $ctx, int $status): array;
}
