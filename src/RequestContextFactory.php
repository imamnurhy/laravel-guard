<?php

namespace AppGuard;

use AppGuard\Core\RequestContext;
use Illuminate\Http\Request;

final class RequestContextFactory
{
    /** @var null|callable(Request): mixed */
    private $userResolver = null;

    /** @var null|callable(Request): ?string */
    private $tenantResolver = null;

    public function __construct(private array $config = [])
    {
    }

    public function resolveUserUsing(?callable $resolver): self
    {
        $this->userResolver = $resolver;
        return $this;
    }

    public function resolveTenantUsing(?callable $resolver): self
    {
        $this->tenantResolver = $resolver;
        return $this;
    }

    /**
     * @param bool $withUser true hanya di fase POST atau bila user sudah terotentikasi.
     */
    public function make(Request $request, bool $withUser = false): RequestContext
    {
        $userId = null;
        $roles = [];
        $user = $this->userResolver !== null
            ? ($this->userResolver)($request)
            : (($withUser || $request->user()) ? $request->user() : null);

        if ($user !== null) {
            if (is_object($user)) {
                $userId = (string) ($user->id ?? (method_exists($user, 'getAuthIdentifier') ? $user->getAuthIdentifier() : ''));
                if (isset($user->role) && is_scalar($user->role)) {
                    $roles[] = (string) $user->role;
                }
                if (method_exists($user, 'getRoleNames')) {
                    try {
                        foreach ($user->getRoleNames() as $r) {
                            $roles[] = (string) $r;
                        }
                    } catch (\Throwable) {
                    }
                }
            } elseif (is_scalar($user)) {
                $userId = (string) $user;
            }
        }

        $tenant = $this->tenantResolver !== null
            ? ($this->tenantResolver)($request)
            : ($this->config['control_plane']['app_key'] ?? null);

        $trapFields = array_values(array_filter(
            $this->config['detectors']['honeypot']['fields'] ?? [],
            fn ($field) => filled($request->input($field)),
        ));

        // Ambil payload input (kecuali file upload dan safe fields) untuk inspeksi detector
        $inputs = [];
        try {
            $inputs = $request->except(['_token', 'password', 'password_confirmation']);
        } catch (\Throwable) {
            $inputs = [];
        }

        $sensorToken = $request->header('X-Guard-Sensor-Token') ?: $request->cookie('guard_sensor_token');

        return new RequestContext(
            ip: (string) $this->resolveClientIp($request),
            method: $request->method(),
            path: rawurldecode($request->getPathInfo()),
            userAgent: (string) $request->userAgent(),
            routeName: $request->route()?->getName(),
            userId: $userId !== '' ? $userId : null,
            identifier: $this->identifier($request),
            attributes: [
                'honeypot_fields' => $trapFields,
                'inputs' => $inputs,
                'headers' => $request->headers->all(),
                'roles' => array_values(array_unique($roles)),
                'tenant' => $tenant,
                'route_parameters' => $request->route()?->parameters() ?? [],
                'sensor_token' => $sensorToken,
            ],
        );
    }

    public function identifier(Request $request): ?string
    {
        foreach ($this->config['identifier_keys'] ?? [] as $key) {
            $value = $request->input($key);
            if (is_string($value) && $value !== '') {
                return $value;
            }
        }

        return null;
    }

    /**
     * Resolusi client IP ramah reverse proxy & Docker container.
     */
    public function resolveClientIp(Request $request): string
    {
        // 1. Jika Laravel sudah memiliki IP valid via TrustProxies, utamakan $request->ip()
        $clientIp = $request->ip();
        if ($clientIp && filter_var($clientIp, FILTER_VALIDATE_IP)) {
            // Jika bukan loopback / private IP atau jika tidak ada header reverse proxy khusus, gunakan ini
            if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
                return $_SERVER['HTTP_CF_CONNECTING_IP'];
            }
            return (string) $clientIp;
        }

        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }

        if (!empty($_SERVER['HTTP_X_REAL_IP']) && filter_var($_SERVER['HTTP_X_REAL_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_X_REAL_IP'];
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $firstIp = trim($ips[0] ?? '');
            if (filter_var($firstIp, FILTER_VALIDATE_IP)) {
                return $firstIp;
            }
        }

        return (string) $clientIp ?: '127.0.0.1';
    }
}
