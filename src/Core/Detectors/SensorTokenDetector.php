<?php

namespace AppGuard\Core\Detectors;

use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

/**
 * Detektor Token Integritas Guard Sensor (Client security integrity verification).
 * Verifikasi dilakukan secara lokal/offline dengan secret_hash tanpa memanggil Control Plane.
 * Jika sensor mati/token absen pada browser normal, fail-open (degraded mode, tidak memblokir pengguna).
 */
final class SensorTokenDetector extends AbstractDetector
{
    public function __construct(private array $config = [])
    {
    }

    public function name(): string
    {
        return 'sensor_token';
    }

    public function inspect(RequestContext $ctx): array
    {
        $enabled = (bool) ($this->config['enabled'] ?? true);
        if (! $enabled) {
            return [];
        }

        // Token dapat dikirim via Header HTTP atau Cookie
        $token = $ctx->attributes['sensor_token'] ?? null;
        if (! $token || ! is_string($token)) {
            // Mode degraded: Token absen tidak langsung memblokir untuk fail-safe
            return [];
        }

        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return [
                new Signal('sensor_tampered', 40, 'Malformed sensor integrity token format', persist: true),
            ];
        }

        [$payloadB64, $signature] = $parts;
        $secret = $this->config['secret_hash'] ?? config('guard.control_plane.app_secret', '');

        if ($secret !== '') {
            $expectedSignature = hash_hmac('sha256', $payloadB64, $secret);
            if (! hash_equals($expectedSignature, $signature)) {
                return [
                    new Signal('sensor_signature_invalid', 50, 'Invalid cryptographic signature on sensor token', persist: true),
                ];
            }
        }

        $payloadJson = base64_decode($payloadB64, true);
        $data = $payloadJson ? json_decode($payloadJson, true) : null;

        if (! is_array($data)) {
            return [
                new Signal('sensor_payload_invalid', 30, 'Unreadable payload inside sensor token', persist: true),
            ];
        }

        // Cek kedaluwarsa token (TTL)
        if (isset($data['exp']) && time() > (int) $data['exp']) {
            return [
                new Signal('sensor_token_expired', 20, 'Expired sensor integrity token', persist: false),
            ];
        }

        // Jika sinyal bot terverifikasi dari browser sensor
        if (! empty($data['bot'])) {
            return [
                new Signal('automated_browser', 45, 'Automated browser/webdriver confirmed by sensor', persist: true),
            ];
        }

        return [];
    }
}
