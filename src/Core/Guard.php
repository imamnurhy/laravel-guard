<?php

namespace AppGuard\Core;

use AppGuard\Core\Contracts\Detector;
use AppGuard\Core\Contracts\Store;
use AppGuard\Core\Contracts\VulnerabilityStore;
use AppGuard\Core\Support\IpMatcher;
use AppGuard\Core\Support\PathMatcher;
use Psr\Log\LoggerInterface;

/**
 * Otak guard: menjalankan detector, menggabungkan skor, memutuskan aksi,
 * dan menyimpan celah/insiden yang terekspose untuk dataset Machine Learning.
 *
 * Tidak bergantung pada Laravel. Tidak menyimpan state antar request (aman untuk Octane).
 */
final class Guard
{
    /** @var null|callable(mixed $user, int $score, string $reason, ?RequestContext $ctx): void */
    private $onUserBannedCallback = null;

    /** @var null|callable(mixed $user, int $score, string $reason, ?RequestContext $ctx): void */
    private $onUserForceLoggedOutCallback = null;

    /** @param Detector[] $detectors */
    public function __construct(
        private Store $store,
        private array $detectors,
        private array $config = [],
        private ?LoggerInterface $logger = null,
        private ?VulnerabilityStore $vulnerabilityStore = null,
    ) {
    }

    public function setOnUserBanned(?callable $callback): self
    {
        $this->onUserBannedCallback = $callback;
        return $this;
    }

    public function setOnUserForceLoggedOut(?callable $callback): self
    {
        $this->onUserForceLoggedOutCallback = $callback;
        return $this;
    }

    public function enabled(): bool
    {
        return (bool) ($this->config['enabled'] ?? true);
    }

    public function enforcing(): bool
    {
        return ($this->config['mode'] ?? 'monitor') === 'enforce';
    }

    public function failOpen(): bool
    {
        return (bool) ($this->config['fail_open'] ?? true);
    }

    /**
     * Memeriksa apakah IP request masuk dalam daftar allowlist (exact IP atau CIDR subnet).
     */
    public function isAllowed(RequestContext $ctx): bool
    {
        $allowlist = $this->config['allowlist'] ?? [];
        if (empty($allowlist) || $ctx->ip === '') {
            return false;
        }

        return IpMatcher::matches($ctx->ip, $allowlist);
    }

    /** Fase PRE: periksa request sebelum controller. */
    public function inspect(RequestContext $ctx): Decision
    {
        if ($this->isAllowed($ctx)) {
            return Decision::allow();
        }

        if ($this->store->has($this->blockKey($ctx->ip))) {
            return $this->log($ctx, new Decision(
                Action::Block,
                100,
                [new Signal('blocklist', 100, 'IP is manually blocked')],
            ));
        }

        // Cek jika user ID sedang dalam status banned di cache
        if ($ctx->userId !== null && $this->store->has("block:user:{$ctx->userId}")) {
            return $this->log($ctx, new Decision(
                Action::Block,
                100,
                [new Signal('user_ban', 100, 'User account is banned')],
            ));
        }

        // Cek jika user ID sedang dalam status force logout (Tier 1 Soft Action)
        if ($ctx->userId !== null && $this->store->has("force_logout:user:{$ctx->userId}")) {
            $this->store->forget("force_logout:user:{$ctx->userId}");
            return $this->log($ctx, new Decision(
                Action::Block,
                100,
                [new Signal('user_force_logout', 100, 'User session was force logged out due to repeated anomalies')],
            ));
        }

        $signals = [];
        foreach ($this->detectors as $detector) {
            foreach ($detector->inspect($ctx) as $signal) {
                $signals[] = $signal;
            }
        }

        $score = $this->reputation($ctx) + $this->sum($signals);
        $this->persist($ctx, $signals);

        [$throttleAt, $blockAt] = $this->thresholds($ctx->path);

        $action = match (true) {
            $score >= $blockAt => Action::Block,
            $score >= $throttleAt => Action::Throttle,
            default => Action::Allow,
        };

        // "Throttle" = dibatasi lajunya, bukan ditolak total.
        if ($action === Action::Throttle && ! $this->throttleExceeded($ctx)) {
            $action = Action::Allow;
        }

        $decision = new Decision(
            $action,
            $score,
            $signals,
            $action === Action::Throttle ? 60 : 0,
        );

        // Jika score mencapai batas penalti dan ada user context, evaluasi tindakan penalti (Tiered Defense)
        $banThreshold = (int) ($this->config['user_ban']['threshold'] ?? 100);
        if ($score >= $banThreshold && $ctx->userId !== null) {
            $this->evaluateUserPenalty($ctx, $score, implode('; ', $decision->reasons()), signals: $signals);
        }

        return $this->log($ctx, $decision);
    }

    /** Fase POST: evaluasi respon controller dan simpan celah yang terekspose. */
    public function observe(RequestContext $ctx, int $status): void
    {
        if ($this->isAllowed($ctx)) {
            return;
        }

        foreach ($this->detectors as $detector) {
            $observedSignals = $detector->observe($ctx, $status);
            $this->persist($ctx, $observedSignals);

            // Simpan anomali yang terekspose pada respon tertentu
            if (!empty($observedSignals) && $this->vulnerabilityStore !== null) {
                $reasons = array_map(fn (Signal $s) => "{$s->detector}: {$s->reason}", $observedSignals);
                $this->recordVulnerability([
                    'type' => 'post_observation',
                    'severity' => 'high',
                    'ip' => $ctx->ip,
                    'user_id' => $ctx->userId,
                    'method' => $ctx->method,
                    'path' => $ctx->path,
                    'payload' => $ctx->attributes['inputs'] ?? [],
                    'response_status' => $status,
                    'reasons' => $reasons,
                    'timestamp' => date('Y-m-d H:i:s'),
                ]);
            }
        }
    }

    /**
     * API Manual untuk aplikasi (misal: Controller mencatat IDOR, tampering, atau celah lolos).
     */
    public function recordViolation(mixed $user, string $ruleKey, ?int $points = null, ?string $reason = null, ?RequestContext $ctx = null): bool
    {
        if (! $this->enabled()) {
            return false;
        }

        $userId = is_object($user) ? ($user->id ?? $user->getAuthIdentifier()) : (string) $user;
        $ip = $ctx?->ip ?? (function_exists('request') && request() ? request()->ip() : '127.0.0.1');

        $rules = $this->config['rules'] ?? [];
        $pts = $points ?? ($rules[$ruleKey]['points'] ?? 25);
        $desc = $reason ?? ($rules[$ruleKey]['description'] ?? "Violation: {$ruleKey}");
        $ttl = (int) ($this->config['reputation_ttl'] ?? 1800);
        $threshold = (int) ($this->config['user_ban']['threshold'] ?? 100);

        // Periksa cap skor per rule (mencegah 1 anomali berulang menembus batas ban)
        $ruleCaps = $this->config['user_ban']['rule_score_caps'] ?? [];
        $ruleCap = (int) ($ruleCaps[$ruleKey] ?? 0);
        $ptsToAdd = $pts;

        if ($ruleCap > 0) {
            $currentRuleScore = $this->store->count("score:user:{$userId}:rule:{$ruleKey}");
            if ($currentRuleScore >= $ruleCap) {
                $ptsToAdd = 0;
            } else {
                $ptsToAdd = min($pts, $ruleCap - $currentRuleScore);
            }
        }

        if ($ptsToAdd > 0) {
            if ($ruleCap > 0) {
                $this->store->hit("score:user:{$userId}:rule:{$ruleKey}", $ttl, $ptsToAdd);
            }
            $userScore = $this->store->hit("score:user:{$userId}", $ttl, $ptsToAdd);
            if ($ip !== '127.0.0.1') {
                $this->store->hit("score:ip:{$ip}", $ttl, $ptsToAdd);
            }
        } else {
            $userScore = $this->store->count("score:user:{$userId}");
        }

        // Catat ke Vulnerability Store sebagai celah/insiden yang terkonfirmasi
        if ($this->vulnerabilityStore !== null) {
            $this->recordVulnerability([
                'type' => 'application_violation',
                'severity' => $pts >= 50 ? 'critical' : 'warning',
                'rule_key' => $ruleKey,
                'points' => $pts,
                'ip' => $ip,
                'user_id' => $userId,
                'method' => $ctx?->method ?? 'UNKNOWN',
                'path' => $ctx?->path ?? 'UNKNOWN',
                'payload' => $ctx?->attributes['inputs'] ?? [],
                'response_status' => 403,
                'reasons' => [$desc],
                'timestamp' => date('Y-m-d H:i:s'),
            ]);
        }

        if ($this->logger) {
            $this->logger->warning("guard.violation", [
                'user_id' => $userId,
                'rule' => $ruleKey,
                'points' => $pts,
                'total_score' => $userScore,
                'threshold' => $threshold,
                'reason' => $desc,
            ]);
        }

        // Cek ambang batas penalti user (Tiered Defense)
        if ($userScore >= $threshold) {
            $ruleSeverity = $rules[$ruleKey]['severity'] ?? null;
            $this->evaluateUserPenalty(
                $ctx ?? new RequestContext($ip, 'POST', '/', userId: (string)$userId),
                $userScore,
                $desc,
                $user,
                ruleKey: $ruleKey,
                severity: $ruleSeverity
            );
            return true;
        }

        return false;
    }

    /**
     * Catat langsung sebuah celah/bypass yang berhasil terekspose
     * (untuk disimpan sebagai dataset latihan Machine Learning).
     */
    public function recordVulnerability(array $incident): void
    {
        if ($this->vulnerabilityStore !== null) {
            $this->vulnerabilityStore->recordExposed($incident);
        }
    }

    public function block(string $ip, int $seconds): void
    {
        $this->store->put($this->blockKey($ip), 1, $seconds);
    }

    public function unblock(string $ip): void
    {
        $this->store->forget($this->blockKey($ip));
        $this->store->forget("score:ip:{$ip}");
    }

    public function isBlocked(string $ip): bool
    {
        return $this->store->has($this->blockKey($ip));
    }

    public function scoreOf(string $ip): int
    {
        return $this->store->count("score:ip:{$ip}");
    }

    public function scoreOfUser(string|int $userId): int
    {
        return $this->store->count("score:user:{$userId}");
    }

    public function unbanUser(string|int $userId): void
    {
        $this->store->forget("block:user:{$userId}");
        $this->store->forget("guard:user_banned:{$userId}");
        $this->store->forget("score:user:{$userId}");
        $this->store->forget("force_logout:user:{$userId}");

        $ruleCaps = $this->config['user_ban']['rule_score_caps'] ?? [];
        foreach (array_keys($ruleCaps) as $ruleKey) {
            $this->store->forget("score:user:{$userId}:rule:{$ruleKey}");
        }

        if (class_exists(\Illuminate\Support\Facades\Cache::class)) {
            \Illuminate\Support\Facades\Cache::forget("block:user:{$userId}");
            \Illuminate\Support\Facades\Cache::forget("guard:user_banned:{$userId}");
            \Illuminate\Support\Facades\Cache::forget("score:user:{$userId}");
            \Illuminate\Support\Facades\Cache::forget("force_logout:user:{$userId}");
        }
    }

    public function isUserBanned(string|int $userId): bool
    {
        if ($this->store->has("block:user:{$userId}")) {
            return true;
        }

        if (class_exists(\Illuminate\Support\Facades\Cache::class)) {
            return \Illuminate\Support\Facades\Cache::has("block:user:{$userId}");
        }

        return false;
    }

    public function isUserForceLoggedOut(string|int $userId): bool
    {
        if ($this->store->has("force_logout:user:{$userId}")) {
            return true;
        }

        if (class_exists(\Illuminate\Support\Facades\Cache::class)) {
            return \Illuminate\Support\Facades\Cache::has("force_logout:user:{$userId}");
        }

        return false;
    }

    // ------------------------------------------------------------------

    private function evaluateUserPenalty(
        RequestContext $ctx,
        int $score,
        string $reason,
        mixed $userObject = null,
        array $signals = [],
        ?string $ruleKey = null,
        ?string $severity = null
    ): void {
        if (! ($this->config['user_ban']['enabled'] ?? true)) {
            return;
        }

        $userId = $ctx->userId;
        if (! $userId) {
            return;
        }

        // Cek apakah pelanggaran termasuk kategori Critical / Hard Ban
        $criticalRules = $this->config['user_ban']['critical_rules'] ?? ['sqli', 'malicious_upload', 'path_traversal'];
        $banSeverities = $this->config['user_ban']['ban_severities'] ?? ['critical'];

        $isCritical = false;

        if ($ruleKey && in_array($ruleKey, $criticalRules, true)) {
            $isCritical = true;
        }

        if ($severity && in_array($severity, $banSeverities, true)) {
            $isCritical = true;
        }

        foreach ($signals as $signal) {
            if (in_array($signal->detector, $criticalRules, true)) {
                $isCritical = true;
                break;
            }
            $ruleConfig = $this->config['rules'][$signal->detector] ?? [];
            if (in_array($ruleConfig['severity'] ?? '', $banSeverities, true)) {
                $isCritical = true;
                break;
            }
        }

        if ($isCritical) {
            // TIER 2: HARD ACTION (Permanent Database Ban)
            $this->evaluateUserBan($ctx, $score, $reason, $userObject);
        } else {
            // TIER 1: SOFT ACTION (Force Logout, reset score, akun database aman)
            $this->evaluateUserForceLogout($ctx, $score, $reason, $userObject);
        }
    }

    private function evaluateUserBan(RequestContext $ctx, int $score, string $reason, mixed $userObject = null): void
    {
        $userId = $ctx->userId;
        if (! $userId) {
            return;
        }

        $ttl = (int) ($this->config['user_ban']['duration'] ?? 604800); // 7 hari
        $this->store->put("block:user:{$userId}", 1, $ttl);

        if ($this->onUserBannedCallback !== null) {
            ($this->onUserBannedCallback)($userObject ?? $userId, $score, $reason, $ctx);
        }
    }

    private function evaluateUserForceLogout(RequestContext $ctx, int $score, string $reason, mixed $userObject = null): void
    {
        $userId = $ctx->userId;
        if (! $userId) {
            return;
        }

        // Tandai user untuk diputus sesinya pada request aktif (10 menit)
        $this->store->put("force_logout:user:{$userId}", 1, 600);

        // Reset reputasi score user agar tidak terjebak loop setelah login kembali
        $this->store->forget("score:user:{$userId}");

        if ($this->onUserForceLoggedOutCallback !== null) {
            ($this->onUserForceLoggedOutCallback)($userObject ?? $userId, $score, $reason, $ctx);
        }
    }

    private function reputation(RequestContext $ctx): int
    {
        $ip = $this->store->count("score:ip:{$ctx->ip}");
        $user = $ctx->userId !== null ? $this->store->count("score:user:{$ctx->userId}") : 0;

        return max($ip, $user);
    }

    /** @param Signal[] $signals */
    private function persist(RequestContext $ctx, array $signals): void
    {
        $ttl = (int) ($this->config['reputation_ttl'] ?? 900);

        foreach ($signals as $signal) {
            if (! $signal->persist) {
                continue;
            }

            $this->store->hit("score:ip:{$ctx->ip}", $ttl, $signal->score);

            if ($ctx->userId !== null) {
                $ruleCaps = $this->config['user_ban']['rule_score_caps'] ?? [];
                $cap = (int) ($ruleCaps[$signal->detector] ?? 0);
                $ptsToAdd = $signal->score;

                if ($cap > 0) {
                    $current = $this->store->count("score:user:{$ctx->userId}:rule:{$signal->detector}");
                    if ($current >= $cap) {
                        $ptsToAdd = 0;
                    } else {
                        $ptsToAdd = min($ptsToAdd, $cap - $current);
                    }
                }

                if ($ptsToAdd > 0) {
                    if ($cap > 0) {
                        $this->store->hit("score:user:{$ctx->userId}:rule:{$signal->detector}", $ttl, $ptsToAdd);
                    }
                    $this->store->hit("score:user:{$ctx->userId}", $ttl, $ptsToAdd);
                }
            }

            // Catat ke Vulnerability Store sebagai insiden terdeteksi jika memiliki skor ancaman tinggi
            if ($this->vulnerabilityStore !== null && $signal->score >= 35) {
                $this->recordVulnerability([
                    'type' => $signal->detector,
                    'severity' => $signal->score >= 100 ? 'critical' : ($signal->score >= 50 ? 'high' : 'warning'),
                    'score' => $signal->score,
                    'ip' => $ctx->ip,
                    'user_id' => $ctx->userId,
                    'method' => $ctx->method,
                    'path' => $ctx->path,
                    'payload' => $ctx->attributes['inputs'] ?? [],
                    'reasons' => [$signal->reason],
                    'user_agent' => $ctx->attributes['headers']['user-agent'][0] ?? null,
                    'timestamp' => date('Y-m-d H:i:s'),
                ]);
            }
        }
    }

    /** @param Signal[] $signals */
    private function sum(array $signals): int
    {
        return array_sum(array_map(fn (Signal $s) => $s->score, $signals));
    }

    /** @return array{0:int,1:int} */
    private function thresholds(string $path): array
    {
        $t = $this->config['thresholds'] ?? ['throttle' => 50, 'block' => 100];

        foreach ($this->config['profiles'] ?? [] as $profile) {
            if (PathMatcher::matches($profile['paths'] ?? [], $path) !== null) {
                $t = array_merge($t, array_intersect_key($profile, ['throttle' => 1, 'block' => 1]));
                break;
            }
        }

        return [(int) $t['throttle'], (int) $t['block']];
    }

    private function throttleExceeded(RequestContext $ctx): bool
    {
        $limit = (int) ($this->config['throttle_per_minute'] ?? 10);

        return $this->store->hit("throttle:{$ctx->ip}", 60) > $limit;
    }

    private function blockKey(string $ip): string
    {
        return "block:ip:{$ip}";
    }

    private function log(RequestContext $ctx, Decision $decision): Decision
    {
        if ($this->logger && ($decision->signals !== [] || ! $decision->isAllowed())) {
            $this->logger->warning('guard.decision', [
                'action' => $decision->action->value,
                'enforced' => $this->enforcing(),
                'score' => $decision->score,
                'ip' => $ctx->ip,
                'method' => $ctx->method,
                'path' => $ctx->path,
                'user' => $ctx->userId,
                'reasons' => $decision->reasons(),
            ]);
        }

        return $decision;
    }
}
