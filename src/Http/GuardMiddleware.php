<?php

namespace AppGuard\Http;

use AppGuard\Attributes\GuardProfile;
use AppGuard\Core\Action;
use AppGuard\Core\Decision;
use AppGuard\Core\Guard;
use AppGuard\Handlers\DefaultUserBanHandler;
use AppGuard\RequestContextFactory;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use ReflectionClass;
use ReflectionMethod;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Terdaftar sebagai middleware GLOBAL (setelah TrustProxies), bukan di group web/api,
 * supaya URL yang tidak punya route (target scanner: /.env, /wp-admin) juga terlihat.
 *
 * PRE  (handle)    : IP-level & User-level check, pencegahan dini sebelum ke controller.
 * POST (terminate) : route + user + status response sudah diketahui, berjalan setelah response terkirim.
 */
class GuardMiddleware
{
    public function __construct(
        private Guard $guard,
        private RequestContextFactory $factory,
        private DefaultUserBanHandler $banHandler
    ) {}

    public function handle(Request $request, Closure $next, string ...$parameters): Response
    {
        if (! $this->guard->enabled()) {
            return $next($request);
        }

        // Cek apakah user yang sedang login berstatus banned di model aplikasi berdasarkan konfigurasi
        if ($user = $request->user()) {
            $attributes = config('guard.user_ban.attributes', []);

            foreach ($attributes as $col => $val) {
                if (isset($user->{$col}) && (int) $user->{$col} === (int) $val) {
                    return $this->banHandler->forceLogout($request, 'Akun Anda telah dinonaktifkan.');
                }
            }
        }

        $overrides = array_merge(
            $this->extractAttributeOverrides($request),
            $this->parseMiddlewareParameters($parameters),
        );

        try {
            $decision = $this->guard->inspect($this->factory->make($request), $overrides);
        } catch (Throwable $e) {
            report($e);

            return $this->guard->failOpen()
                ? $next($request)
                : new Response('Service Unavailable', 503);
        }

        $effectiveEnforcing = isset($overrides['mode'])
            ? $overrides['mode'] === 'enforce'
            : $this->guard->enforcing();

        if (! $decision->isAllowed() && $effectiveEnforcing) {
            // Jika user terblokir atau diputus sesinya dan sedang login, force logout seketika
            if ($request->user()) {
                $signalDetectors = array_column($decision->signals, 'detector');
                if (in_array('user_ban', $signalDetectors, true)) {
                    return $this->banHandler->forceLogout($request, 'Akun Anda telah dinonaktifkan oleh sistem keamanan.');
                }
                if (in_array('user_force_logout', $signalDetectors, true)) {
                    return $this->banHandler->forceLogout($request, 'Sesi Anda telah diakhiri demi keamanan karena aktivitas formulir terdeteksi tidak wajar. Silakan login kembali.');
                }
            }

            return $this->reject($request, $decision);
        }

        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        if (! $this->guard->enabled()) {
            return;
        }

        try {
            $this->guard->observe($this->factory->make($request, withUser: true), $response->getStatusCode());
        } catch (Throwable $e) {
            report($e);
        }
    }

    private function reject(Request $request, Decision $decision): Response
    {
        if ($responder = $this->guard->customResponder()) {
            $custom = $responder($request, $decision);
            if ($custom instanceof Response) {
                return $custom;
            }
        }

        $throttled = $decision->action === Action::Throttle;
        $status = $throttled ? 429 : 403;
        $headers = $throttled ? ['Retry-After' => (string) $decision->retryAfter] : [];

        // Alasan sengaja tidak dikirim ke client (jangan bocorkan aturan deteksi).
        if ($request->expectsJson()) {
            return new JsonResponse(['message' => $throttled ? 'Too Many Requests.' : 'Forbidden.'], $status, $headers);
        }

        $viewName = $throttled
            ? (string) config('guard.responses.views.throttle', 'guard::throttled')
            : (string) config('guard.responses.views.block', 'guard::blocked');

        if (function_exists('view') && view()->exists($viewName)) {
            return new Response(view($viewName, [
                'decision'   => $decision,
                'throttled'  => $throttled,
                'retryAfter' => $decision->retryAfter,
            ])->render(), $status, array_merge($headers, ['Content-Type' => 'text/html; charset=UTF-8']));
        }

        return new Response($throttled ? 'Too Many Requests' : 'Forbidden', $status, $headers);
    }

    /**
     * Parse parameter middleware seperti `guard:strict,threshold=60` atau `guard:waf,honeypot,mode=monitor`.
     *
     * @param string[] $parameters
     * @return array<string, mixed>
     */
    public function parseMiddlewareParameters(array $parameters): array
    {
        $overrides = [];
        $detectors = [];
        $knownProfiles = array_merge(['strict', 'balanced', 'monitor'], array_keys((array) config('guard.profiles', [])));

        foreach ($parameters as $raw) {
            $token = trim($raw);
            if ($token === '') {
                continue;
            }

            if ($token === 'bypass' || $token === 'off') {
                $overrides['bypass'] = true;
                continue;
            }

            if (str_contains($token, '=')) {
                [$k, $v] = array_map('trim', explode('=', $token, 2));
                $k = strtolower($k);
                if ($k === 'threshold' || $k === 'block') {
                    $overrides['block'] = (int) $v;
                } elseif ($k === 'throttle') {
                    $overrides['throttle'] = (int) $v;
                } elseif ($k === 'mode') {
                    $overrides['mode'] = strtolower($v);
                } elseif ($k === 'profile') {
                    $overrides['profile'] = $v;
                } elseif ($k === 'detectors' || $k === 'detector') {
                    foreach (explode('|', $v) as $d) {
                        if (trim($d) !== '') {
                            $detectors[] = trim($d);
                        }
                    }
                }
                continue;
            }

            if (in_array($token, $knownProfiles, true) && ! isset($overrides['profile'])) {
                $overrides['profile'] = $token;
                if ($token === 'monitor') {
                    $overrides['mode'] = 'monitor';
                }
            } else {
                $detectors[] = $token;
            }
        }

        if ($detectors !== []) {
            $overrides['detectors'] = array_values(array_unique($detectors));
        }

        return $overrides;
    }

    /** @return array<string, mixed> */
    private function extractAttributeOverrides(Request $request): array
    {
        $route = $request->route();
        if (! $route) {
            return [];
        }

        try {
            $controller = $route->getController();
            $method = $route->getActionMethod();
            if (! is_object($controller)) {
                return [];
            }

            $overrides = [];
            $refClass = new ReflectionClass($controller);
            foreach ($refClass->getAttributes(GuardProfile::class) as $attr) {
                $overrides = array_merge($overrides, $attr->newInstance()->toOverrides());
            }

            if ($method && $refClass->hasMethod($method)) {
                $refMethod = new ReflectionMethod($controller, $method);
                foreach ($refMethod->getAttributes(GuardProfile::class) as $attr) {
                    $overrides = array_merge($overrides, $attr->newInstance()->toOverrides());
                }
            }

            return $overrides;
        } catch (Throwable) {
            return [];
        }
    }
}
