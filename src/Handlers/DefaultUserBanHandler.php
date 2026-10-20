<?php

namespace AppGuard\Handlers;

use AppGuard\Core\BanRecord;
use AppGuard\Core\Contracts\BanRegistry;
use AppGuard\Core\Contracts\VulnerabilityStore;
use AppGuard\Core\RequestContext;
use AppGuard\Events\UserBanned;
use AppGuard\Events\UserForceLoggedOut;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class DefaultUserBanHandler
{
    public function __construct(
        private ?VulnerabilityStore $vulnerabilityStore = null,
        private ?BanRegistry $banRegistry = null,
    ) {
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
        $ttl = (int) config('guard.user_ban.duration', 604800);
        Cache::put("block:user:{$userId}", 1, now()->addSeconds($ttl));

        if ($this->banRegistry !== null && $userId !== null && $userId !== '') {
            $now = time();
            $this->banRegistry->record(new BanRecord(
                type: BanRecord::TYPE_USER,
                subject: (string) $userId,
                reason: $reason,
                source: $context ? 'user_ban' : 'manual',
                score: $score,
                bannedAt: $now,
                expiresAt: $ttl > 0 ? $now + $ttl : null,
                ip: $ip,
                meta: array_filter(['label' => $username !== (string) $userId ? $username : null, 'url' => $url]),
            ));
        }

        // 3. Trigger Laravel Event agar aplikasi induk bisa menjalankan custom hook
        $now = time();
        $expiresAt = $ttl > 0 ? $now + $ttl : null;
        $tenant = (string) ($context->attributes['tenant'] ?? config('guard.control_plane.app_key', ''));
        event(new UserBanned(
            user: $user,
            score: $score,
            reason: $reason,
            context: $context,
            bannedAt: $now,
            expiresAt: $expiresAt,
            detector: 'user_ban',
            tenant: $tenant !== '' ? $tenant : null,
        ));

        // 4. Catat ke Vulnerability Store / Buffer telemetri agar segera dikirim ke Control Plane
        // Notifikasi darurat (Telegram/Tebot) sepenuhnya ditangani oleh Control Plane secara terpusat
        if ($this->vulnerabilityStore !== null) {
            $this->vulnerabilityStore->recordExposed([
                'type' => 'ban.created',
                'ban_type' => BanRecord::TYPE_USER,
                'severity' => 'critical',
                'rule_key' => 'user_ban',
                'score' => $score,
                'ip' => $ip,
                'user_id' => $userId,
                'subject' => (string) $userId,
                'username' => $username,
                'tenant' => $tenant !== '' ? $tenant : null,
                'method' => $context?->method ?? request()->method(),
                'path' => $context?->path ?? request()->path(),
                'payload' => [
                    'reason' => $reason,
                    'url' => $url,
                ],
                'response_status' => 403,
                'reasons' => [$reason],
                'banned_at' => date('Y-m-d H:i:s', $now),
                'expires_at' => $expiresAt ? date('Y-m-d H:i:s', $expiresAt) : null,
                'timestamp' => date('Y-m-d H:i:s', $now),
            ]);
        }
    }

    /**
     * Buka blokir akun user di cache dan opsional sinkronkan status ke database.
     */
    public function unban(mixed $user, bool $syncDb = false): void
    {
        $userId = is_object($user) ? ($user->id ?? $user->getAuthIdentifier()) : $user;
        if (! $userId) {
            return;
        }

        // 1. Bersihkan seluruh key cache pemblokiran dan reputasi
        Cache::forget("block:user:{$userId}");
        Cache::forget("guard:user_banned:{$userId}");
        Cache::forget("score:user:{$userId}");
        Cache::forget("force_logout:user:{$userId}");

        if ($this->banRegistry !== null) {
            $this->banRegistry->remove(BanRecord::TYPE_USER, (string) $userId);
        }

        // 2. Sinkronkan pemulihan status di database jika diminta
        if ($syncDb) {
            $modelClass = config('guard.user_ban.model');
            $attributes = config('guard.user_ban.attributes', []);

            if ($modelClass && class_exists($modelClass) && !empty($attributes)) {
                $unbanAttributes = [];
                foreach ($attributes as $col => $val) {
                    $unbanAttributes[$col] = is_int($val) ? 0 : (is_bool($val) ? false : 0);
                }

                try {
                    $modelClass::whereKey($userId)->update($unbanAttributes);
                    if (is_object($user)) {
                        foreach ($unbanAttributes as $col => $val) {
                            if (isset($user->{$col})) {
                                $user->{$col} = $val;
                            }
                        }
                    }
                } catch (\Throwable $e) {
                    Log::channel(config('guard.log_channel'))->error("[AppGuard] Failed to reset user status attributes on unban: " . $e->getMessage());
                }
            }
        }
    }

    /**
     * Eksekusi pemutusan sesi paksa (Soft Action) tanpa mengubah status akun di database.
     */
    public function handleForceLogout(mixed $user, int $score, string $reason, ?RequestContext $context = null): void
    {
        $userId = is_object($user) ? ($user->id ?? $user->getAuthIdentifier()) : $user;
        $username = is_object($user) ? ($user->username ?? $user->email ?? (string)$userId) : (string)$userId;
        $ip = $context?->ip ?? request()->ip() ?? '127.0.0.1';
        $url = request()->fullUrl();

        // 1. Simpan metadata pemutusan sesi di Cache sementara (15 menit)
        Cache::put("guard:user_force_logout:{$userId}", [
            'reason' => $reason,
            'score' => $score,
            'logged_out_at' => date('Y-m-d H:i:s'),
            'ip' => $ip,
        ], now()->addMinutes(15));

        // 2. Trigger Event UserForceLoggedOut
        event(new UserForceLoggedOut($user, $score, $reason, $context));

        // 3. Catat telemetri sebagai medium severity event
        if ($this->vulnerabilityStore !== null) {
            $this->vulnerabilityStore->recordExposed([
                'type' => 'user_force_logout',
                'severity' => 'medium',
                'rule_key' => 'user_force_logout',
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
    public function forceLogout(Request $request, ?string $reason = null): Response
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

        $message = $reason ?? 'Sesi Anda telah diakhiri demi keamanan karena aktivitas formulir terdeteksi tidak wajar. Silakan login kembali.';

        if ($request->expectsJson() || $request->isXmlHttpRequest()) {
            return new JsonResponse([
                'success' => false,
                'force_logout' => true,
                'message' => $message,
            ], 403);
        }

        $redirectRoute = config('guard.user_ban.redirect_route', 'login');

        return redirect()->route($redirectRoute)->withErrors([
            'username' => $message,
        ]);
    }
}
