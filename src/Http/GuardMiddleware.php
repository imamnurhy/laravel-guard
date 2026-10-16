<?php

namespace AppGuard\Http;

use AppGuard\Core\Action;
use AppGuard\Core\Decision;
use AppGuard\Core\Guard;
use AppGuard\Handlers\DefaultUserBanHandler;
use AppGuard\RequestContextFactory;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
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

    public function handle(Request $request, Closure $next, ?string $profile = null): Response
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

        try {
            $decision = $this->guard->inspect($this->factory->make($request));
        } catch (Throwable $e) {
            report($e);

            return $this->guard->failOpen()
                ? $next($request)
                : new Response('Service Unavailable', 503);
        }

        if (! $decision->isAllowed() && $this->guard->enforcing()) {
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
        $throttled = $decision->action === Action::Throttle;
        $status = $throttled ? 429 : 403;
        $headers = $throttled ? ['Retry-After' => (string) $decision->retryAfter] : [];

        // Alasan sengaja tidak dikirim ke client (jangan bocorkan aturan deteksi).
        return $request->expectsJson()
            ? new JsonResponse(['message' => $throttled ? 'Too Many Requests.' : 'Forbidden.'], $status, $headers)
            : new Response($throttled ? 'Too Many Requests' : 'Forbidden', $status, $headers);
    }
}
