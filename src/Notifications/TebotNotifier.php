<?php

namespace AppGuard\Notifications;

use Explorin\Tebot\Services\Tebot;
use Illuminate\Support\Facades\Log;

/**
 * Notifier darurat via Tebot Telegram.
 * Failsafe: Jika Tebot tidak terpasang di project, otomatis fallback ke Log biasa.
 */
final class TebotNotifier
{
    public function sendAlert(string $title, string $reason, string $ip, string $url, array $details = []): void
    {
        if (!config('guard.tebot.enabled', true)) {
            return;
        }

        try {
            $userPart = '';
            if (!empty($details['user_id']) || !empty($details['username'])) {
                $userPart = sprintf(
                    "• <b>User ID:</b> %s\n• <b>Username:</b> %s\n",
                    htmlspecialchars((string)($details['user_id'] ?? '-'), ENT_QUOTES),
                    htmlspecialchars((string)($details['username'] ?? '-'), ENT_QUOTES)
                );
            }

            $message = sprintf(
                "🚨 <b>[%s]</b>\n\n%s" .
                "• <b>Alasan:</b> %s\n" .
                "• <b>Endpoint:</b> <code>%s</code>\n" .
                "• <b>Client IP:</b> <code>%s</code>\n" .
                "• <b>Aksi:</b> %s",
                htmlspecialchars($title, ENT_QUOTES),
                $userPart,
                htmlspecialchars($reason, ENT_QUOTES),
                htmlspecialchars($url, ENT_QUOTES),
                htmlspecialchars($ip, ENT_QUOTES),
                htmlspecialchars((string)($details['action'] ?? 'Auto-Banned & Protected'), ENT_QUOTES)
            );

            if (class_exists(Tebot::class) && config('tebot.enabled', true) && config('tebot.default.key')) {
                Tebot::alert($message, $details)->send();
            } else {
                Log::channel(config('guard.log_channel'))->warning("[AppGuard Alert] {$title}: {$reason}", $details);
            }
        } catch (\Throwable $e) {
            Log::channel(config('guard.log_channel'))->error("[AppGuard] Tebot alert error: " . $e->getMessage());
        }
    }
}
