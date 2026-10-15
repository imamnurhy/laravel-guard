<?php

namespace AppGuard\Handlers;

use AppGuard\Core\Contracts\VulnerabilityStore;
use AppGuard\Core\RequestContext;
use AppGuard\Events\UserBanned;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class DefaultUserBanHandler
{
    public function __construct(private ?VulnerabilityStore $vulnerabilityStore = null)
    {
    }

    /**
     * Eksekusi pemblokiran akun user di database dan cache.
     */
    public function ban(mixed $user, int $score, string $reason, ?RequestContext $context = null): void
    {
        $userId = is_object($user) ? ($user->id ?? $user->getAuthIdentifier()) : $user;
        $username = is_object($user) ? ($user->username ?? $user->email ?? (string)$userId) : (string)$userId;

        // 1. Mutasi kolom-kolom status di database jika model & atribut dikonfigurasi
        $modelClass = config('guard.user_ban.model');
        $attributes = config('guard.user_ban.attributes', []);

        if ($modelClass && class_exists($modelClass) && $userId && !empty($attributes)) {
            try {
                $modelClass::whereKey($userId)->update($attributes);
                if (is_object($user)) {
                    foreach ($attributes as $col => $val) {
                        if (isset($user->{$col})) {
                            $user->{$col} = $val;
                        }
                    }
                }
            } catch (\Throwable $e) {
                Log::channel(config('guard.log_channel'))->error("[AppGuard] Failed to update user status attributes: " . $e->getMessage());
            }
        }

        // 2. Simpan metadata pemblokiran ke Cache
        $ip = $context?->ip ?? request()->ip() ?? '127.0.0.1';
        $url = request()->fullUrl();

        Cache::put("guard:user_banned:{$userId}", [
            'reason' => $reason,
            'score' => $score,
            'banned_at' => date('Y-m-d H:i:s'),
            'ip' => $ip,
        ], now()->addDays(7));

        // Sinkronisasi dengan key block:user: yang dibaca Guard::inspect
        Cache::put("block:user:{$userId}", 1, now()->addDays(7));

        // 3. Trigger Laravel Event agar aplikasi induk bisa menjalankan custom hook
        event(new UserBanned($user, $score, $reason, $context));

        // 4. Catat ke Vulnerability Store / Buffer telemetri agar segera dikirim ke Control Plane
        // Notifikasi darurat (Telegram/Tebot) sepenuhnya ditangani oleh Control Plane secara terpusat
        if ($this->vulnerabilityStore !== null) {
            $this->vulnerabilityStore->recordExposed([
                'type' => 'user_banned',
                'severity' => 'critical',
                'rule_key' => 'user_ban',
                'score' => $score,
                'ip' => $ip,
                'user_id' => $userId,
                'username' => $username,
                'method' => $context?->method ?? request()->method(),
                'path' => $context?->path ?? request()->path(),
                'payload' => [
                    'reason' => $reason,
                    'url' => $url,
                ],
                'response_status' => 403,
                'reasons' => [$reason],
                'timestamp' => date('Y-m-d H:i:s'),
            ]);
        }
    }

    /**
     * Putus sesi aktif secara paksa.
     */
    public function forceLogout(Request $request, string $reason = 'Akun Anda dinonaktifkan oleh sistem keamanan.'): Response
    {
        $user = $request->user();
        if ($user && method_exists($user, 'currentAccessToken') && $user->currentAccessToken()) {
            try {
                $user->currentAccessToken()->delete();
            } catch (\Throwable) {}
        }

        Auth::logout();
        if ($request->hasSession()) {
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }

        $message = 'Akun Anda telah dinonaktifkan oleh sistem keamanan karena aktivitas yang tidak wajar. Silakan hubungi Administrator jika ini merupakan kekeliruan.';

        if ($request->expectsJson() || $request->isXmlHttpRequest()) {
            return new JsonResponse([
                'success' => false,
                'banned' => true,
                'message' => $message,
            ], 403);
        }

        $redirectRoute = config('guard.user_ban.redirect_route', 'login');

        return redirect()->route($redirectRoute)->withErrors([
            'username' => $message,
        ]);
    }
}
