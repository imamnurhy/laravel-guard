<?php

namespace AppGuard\Http;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class SensorProxyController extends Controller
{
    /**
     * Melayani berkas sensor.js dari Control Plane secara aman (reverse-proxy)
     */
    public function script()
    {
        $controlPlaneUrl = rtrim((string) config('guard.control_plane.url', ''), '/');

        // Jika control plane tidak disetel atau fitur dinonaktifkan, kembalikan stub aman (silent fail-open)
        if (empty($controlPlaneUrl) || ! config('guard.enabled', true)) {
            return response("/* AppGuard sensor inactive (standalone mode) */\n", 200, [
                'Content-Type' => 'application/javascript',
            ]);
        }

        $timeout = (int) config('guard.control_plane.timeout', 3);

        // Cache 24 jam agar tenant tidak terus-menerus membebani Control Plane internal
        $script = Cache::remember('app_guard_sensor_script', 86400, function () use ($controlPlaneUrl, $timeout) {
            try {
                $response = Http::timeout($timeout)->get("{$controlPlaneUrl}/sensor.js");

                if ($response->successful()) {
                    return $response->body();
                }
            } catch (\Throwable $e) {
                // Fail-open
            }

            return null;
        });

        if (! $script) {
            return response("/* AppGuard sensor unreachable (fail-open) */\n", 200, [
                'Content-Type' => 'application/javascript',
            ]);
        }

        return response($script, 200, [
            'Content-Type' => 'application/javascript',
            'Cache-Control' => 'public, max-age=86400',
        ]);
    }

    /**
     * Meneruskan sinyal/beacon browser ke Control Plane (reverse-proxy)
     */
    public function beacon(Request $request)
    {
        $controlPlaneUrl = rtrim((string) config('guard.control_plane.url', ''), '/');

        if (! empty($controlPlaneUrl) && config('guard.enabled', true)) {
            $timeout = (int) config('guard.control_plane.timeout', 3);

            try {
                Http::timeout($timeout)
                    ->withHeaders([
                        'X-Forwarded-For' => $request->ip(),
                        'User-Agent' => $request->userAgent() ?? '',
                    ])
                    ->post("{$controlPlaneUrl}/api/v1/sensor/beacon", $request->all());
            } catch (\Throwable $e) {
                // Fail-silent: jangan gagalkan response ke browser
            }
        }

        return response()->json(['status' => 'ok']);
    }
}
