<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\Contracts\Detector;
use AppGuard\Core\RequestContext;

abstract class AbstractDetector implements Detector
{
    public function inspect(RequestContext $ctx): array
    {
        return [];
    }

    public function observe(RequestContext $ctx, int $status): array
    {
        return [];
    }
}
