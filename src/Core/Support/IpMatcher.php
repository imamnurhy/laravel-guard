<?php

namespace AppGuard\Core\Support;

final class IpMatcher
{
    /**
     * Memeriksa apakah sebuah IP cocok dengan daftar IP atau CIDR subnet.
     *
     * @param string $ip IP client yang akan diperiksa
     * @param array<int, string> $patterns Daftar IP (contoh: '127.0.0.1', '::1', '192.168.1.0/24')
     */
    public static function matches(string $ip, array $patterns): bool
    {
        if (empty($patterns) || $ip === '') {
            return false;
        }

        foreach ($patterns as $pattern) {
            $pattern = trim($pattern);
            if ($pattern === '') {
                continue;
            }

            // Exact match (IPv4 atau IPv6)
            if ($ip === $pattern) {
                return true;
            }

            // CIDR Subnet match (misal: 192.168.1.0/24)
            if (str_contains($pattern, '/')) {
                if (self::cidrMatch($ip, $pattern)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Evaluasi CIDR Subnet IPv4.
     */
    private static function cidrMatch(string $ip, string $cidr): bool
    {
        [$subnet, $mask] = explode('/', $cidr, 2);

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $mask = (int) $mask;
        if ($mask < 0 || $mask > 32) {
            return false;
        }

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($mask === 0) {
            return true;
        }

        $maskLong = -1 << (32 - $mask);

        return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
    }
}
