<?php

namespace AppGuard\Core;

enum Action: string
{
    case Allow = 'allow';
    case Throttle = 'throttle';
    case Block = 'block';
}
