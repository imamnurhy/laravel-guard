<?php

namespace AppGuard\Core;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class ControlPlaneClient
{
    protected string $baseUrl;
    protected string $appKey;
    protected string $appSecret;
    protected int $timeout;

    public function __construct(?string $baseUrl = null, ?string $appKey = null, ?string $appSecret = null, int $timeout = 5)
    {
        $this->baseUrl = (string) ($baseUrl ?: config('guard.control_plane.url', ''));
        $this->appKey = (string) ($appKey ?: config('guard.control_plane.app_key', ''));
        $this->appSecret = (string) ($appSecret ?: config('guard.control_plane.app_secret', ''));
        $this->timeout = $timeout ?: (int) config('guard.control_plane.timeout', 5);
    }

    public function isConfigured(): bool
    {
        return ! empty($this->baseUrl) && ! empty($this->appKey) && ! empty($this->appSecret);
    }

    public function getBaseUrl(): string
    {
        return $this->baseUrl;
    }

    public function getAppKey(): string
    {
        return $this->appKey;
    }

    /**
     * Bentuk full URL dan URI path yang selalu konsisten mengarah ke /api/v1/..
     */
    public function resolveEndpoint(string $path): array
    {
        $cleanBase = rtrim($this->baseUrl, '/');
        $cleanPath = '/' . ltrim($path, '/');

        // Jika path belum berawalan /api/v1 dan base belum berakhiran /api/v1
        if (! str_starts_with($cleanPath, '/api/v1') && ! str_ends_with($cleanBase, '/api/v1')) {
            $fullUrl = $cleanBase . '/api/v1' . $cleanPath;
        } else {
            $fullUrl = $cleanBase . $cleanPath;
        }

        $parsedUri = parse_url($fullUrl, PHP_URL_PATH) ?: $cleanPath;

        return [$fullUrl, $parsedUri];
    }

    /**
     * Hitung timestamp dengan toleransi kompensasi offset server
     */
    public function getAdjustedTimestamp(): int
    {
        $offset = (int) Cache::get('guard:server_time_offset', 0);
        return time() + $offset;
    }

    /**
     * Kalibrasi selisih waktu dari header respon HTTP Date jika server mengalami clock skew
     */
    public function calibrateClockOffset(Response $response): void
    {
        $serverDate = $response->header('Date');
        if ($serverDate) {
            $serverTime = strtotime($serverDate);
            if ($serverTime !== false) {
                $offset = $serverTime - time();
                Cache::put('guard:server_time_offset', $offset, 86400);
            }
        }
    }

    /**
     * Buat header otentikasi HMAC-SHA256
     */
    public function generateHmacHeaders(string $method, string $uri, string $rawBody = '', ?int $customTimestamp = null): array
    {
        $timestamp = $customTimestamp ?? $this->getAdjustedTimestamp();
        $nonce = Str::random(16);
        $canonical = strtoupper($method) . "\n{$uri}\n{$timestamp}\n{$nonce}\n{$rawBody}";
        $secretHash = hash('sha256', $this->appSecret);
        $signature = hash_hmac('sha256', $canonical, $secretHash);

        return [
            'X-App-Key' => $this->appKey,
            'X-Timestamp' => (string) $timestamp,
            'X-Nonce' => $nonce,
            'X-Signature' => $signature,
        ];
    }

    /**
     * Kirim HTTP Request dengan auto-healing timestamp saat 401 clock drift terdeteksi
     */
    public function request(string $method, string $path, array $options = []): Response
    {
        [$fullUrl, $uri] = $this->resolveEndpoint($path);

        $body = $options['body'] ?? '';
        $extraHeaders = $options['headers'] ?? [];

        $hmacHeaders = $this->generateHmacHeaders($method, $uri, $body);
        $headers = array_merge($extraHeaders, $hmacHeaders);

        $client = Http::timeout($this->timeout)->withHeaders($headers);

        if (! empty($body)) {
            $client = $client->withBody($body, $headers['Content-Type'] ?? 'application/json');
        }

        $methodLower = strtolower($method);
        /** @var Response $response */
        $response = $client->{$methodLower}($fullUrl);

        // Jika terjadi 401 akibat perbedaan waktu server, lakukan auto-kalibrasi dan ulangi 1 kali
        if ($response->status() === 401 && str_contains($response->body(), 'Timestamp')) {
            $this->calibrateClockOffset($response);

            // Re-generate headers dengan offset baru
            $hmacHeaders = $this->generateHmacHeaders($method, $uri, $body);
            $headers = array_merge($extraHeaders, $hmacHeaders);

            $retryClient = Http::timeout($this->timeout)->withHeaders($headers);
            if (! empty($body)) {
                $retryClient = $retryClient->withBody($body, $headers['Content-Type'] ?? 'application/json');
            }

            $response = $retryClient->{$methodLower}($fullUrl);
        }

        return $response;
    }
}
