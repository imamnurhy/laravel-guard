<?php

namespace AppGuard\Http;

use AppGuard\Core\Contracts\DynamicRuleStore;
use AppGuard\Handlers\DefaultUserBanHandler;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class WebhookController
{
    public function handle(Request $request, DynamicRuleStore $ruleStore)
    {
        $signature = $request->header('X-Guard-Signature');
        $timestamp = (int) $request->header('X-Guard-Timestamp');
        $nonce = $request->header('X-Guard-Nonce');
        $appKey = $request->header('X-Guard-App-Key');

        // 1. Verifikasi Header Wajib
        if (! $signature || ! $timestamp || ! $nonce) {
            return response()->json(['error' => 'Header verifikasi tidak lengkap.'], 400);
        }

        // 2. Anti-Replay Attack (Window waktu 5 menit)
        if (abs(time() - $timestamp) > 300) {
            return response()->json(['error' => 'Timestamp kedaluwarsa atau tidak valid.'], 401);
        }

        $nonceKey = "guard:webhook:nonce:{$nonce}";
        if (Cache::has($nonceKey)) {
            return response()->json(['error' => 'Nonce replay terdeteksi.'], 409);
        }
        Cache::put($nonceKey, 1, 600);

        // 3. Verifikasi Signature HMAC
        $secret = config('guard.control_plane.app_secret', '');
        $jsonPayload = $request->getContent();
        $expectedSignature = hash_hmac('sha256', "{$timestamp}\n{$nonce}\n{$jsonPayload}", $secret);

        if (! hash_equals($expectedSignature, $signature)) {
            return response()->json(['error' => 'Signature webhook tidak valid.'], 403);
        }

        $event = $request->input('event');
        $data = $request->input('data', []);

        // 4. Eksekusi Berdasarkan Event
        try {
            switch ($event) {
                case 'ban_ip':
                    if (! empty($data['ip'])) {
                        $bannedKey = "guard:{$appKey}:banned_ips";
                        $existing = (array) Cache::get($bannedKey, []);
                        if (! in_array($data['ip'], $existing, true)) {
                            $existing[] = $data['ip'];
                            Cache::put($bannedKey, $existing, 86400 * 7);
                        }
                    }
                    break;

                case 'unban_ip':
                    if (! empty($data['ip'])) {
                        $bannedKey = "guard:{$appKey}:banned_ips";
                        $existing = (array) Cache::get($bannedKey, []);
                        $filtered = array_values(array_filter($existing, fn ($ip) => $ip !== $data['ip']));
                        Cache::put($bannedKey, $filtered, 86400 * 7);
                    }
                    break;

                case 'ban_user':
                    if (! empty($data['user_id'])) {
                        $userModel = config('guard.user_ban.model', 'App\\Models\\User');
                        if (class_exists($userModel)) {
                            $user = $userModel::find($data['user_id']);
                            if ($user) {
                                $banHandler = app(DefaultUserBanHandler::class);
                                $banHandler->ban($user, 100, $data['reason'] ?? 'Manual SOC Webhook Ban', null);
                            }
                        }
                    }
                    break;

                case 'policy_updated':
                    if (! empty($data['policy']) && is_array($data['policy'])) {
                        $ruleStore->setPolicy($data['policy']);
                    }
                    break;

                case 'ping':
                    // Health check ping
                    break;
            }

            return response()->json([
                'status' => 'success',
                'event' => $event,
                'message' => 'Webhook berhasil diproses secara aman.',
            ]);
        } catch (\Throwable $e) {
            // Fail-open response
            return response()->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], 500);
        }
    }
}
