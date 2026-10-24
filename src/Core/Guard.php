<?php

namespace AppGuard\Core;

use AppGuard\Core\Contracts\BanRegistry;
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

    /** @var null|callable(BanRecord $ban): void */
    private $onBanCallback = null;

    /** @var null|callable(string $type, string $subject, string $liftedBy, string $reason, ?BanRecord $previous): void */
    private $onBanLiftedCallback = null;

    /** @var null|callable(array<string, mixed> $incident): void */
    private $onIncidentCallback = null;

    /** @var null|callable(RequestContext $ctx, Decision $decision): void */
    private $onScoredCallback = null;

    /** @var null|callable(mixed $request, Decision $decision): mixed */
    private $respondUsingCallback = null;

    /** @var null|callable(mixed $request): mixed */
    private $userResolver = null;

    /** @var null|callable(mixed $request): ?string */
    private $tenantResolver = null;

    /** @param Detector[] $detectors */
    public function __construct(
        private Store $store,
        private array $detectors,
        private array $config = [],
        private ?LoggerInterface $logger = null,
        private ?VulnerabilityStore $vulnerabilityStore = null,
        private ?BanRegistry $banRegistry = null,
    ) {
    }

    public function banRegistry(): ?BanRegistry
    {
        return $this->banRegistry;
    }

    public function vulnerabilityStore(): ?VulnerabilityStore
    {
        return $this->vulnerabilityStore;
    }

    /** @return Detector[] */
    public function detectors(): array
    {
        return $this->detectors;
    }

    public function addDetector(Detector $detector): self
    {
        $this->detectors[] = $detector;
        return $this;
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

    public function onBan(?callable $callback): self
    {
        $this->onBanCallback = $callback;
        return $this;
    }

    public function onBanLifted(?callable $callback): self
    {
        $this->onBanLiftedCallback = $callback;
        return $this;
    }

    public function onIncident(?callable $callback): self
    {
        $this->onIncidentCallback = $callback;
        return $this;
    }

    public function onScored(?callable $callback): self
    {
        $this->onScoredCallback = $callback;
        return $this;
    }

    public function respondUsing(?callable $callback): self
    {
        $this->respondUsingCallback = $callback;
        return $this;
    }

    public function customResponder(): ?callable
    {
        return $this->respondUsingCallback;
    }

    public function resolveUserUsing(?callable $resolver): self
    {
        $this->userResolver = $resolver;
        return $this;
    }

    public function userResolver(): ?callable
    {
        return $this->userResolver;
    }

    public function resolveTenantUsing(?callable $resolver): self
    {
        $this->tenantResolver = $resolver;
        return $this;
    }

    public function tenantResolver(): ?callable
    {
        return $this->tenantResolver;
    }

    public function currentTenant(mixed $request = null): ?string
    {
        if ($this->tenantResolver !== null) {
            return ($this->tenantResolver)($request);
        }

        return isset($this->config['control_plane']['app_key']) && $this->config['control_plane']['app_key'] !== ''
            ? (string) $this->config['control_plane']['app_key']
            : null;
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
     * Memeriksa apakah request masuk dalam daftar allowlist/exclusions
     * (IP/CIDR, path wildcard, user ID, role, atau header).
     */
    public function isAllowed(RequestContext $ctx): bool
    {
        $allowlist = $this->config['allowlist'] ?? [];
        if (! empty($allowlist) && $ctx->ip !== '' && IpMatcher::matches($ctx->ip, $allowlist)) {
            return true;
        }

        $exclusions = $this->config['exclusions'] ?? [];
        if (empty($exclusions)) {
            return false;
        }

        if (! empty($exclusions['ips']) && $ctx->ip !== '' && IpMatcher::matches($ctx->ip, (array) $exclusions['ips'])) {
            return true;
        }

        if (! empty($exclusions['paths']) && PathMatcher::matches((array) $exclusions['paths'], $ctx->path) !== null) {
            return true;
        }

        if (! empty($exclusions['users']) && $ctx->userId !== null) {
            $excludedUsers = array_map('strval', (array) $exclusions['users']);
            if (in_array((string) $ctx->userId, $excludedUsers, true)) {
                return true;
            }
        }

        if (! empty($exclusions['roles'])) {
            $roles = (array) ($ctx->attributes['roles'] ?? []);
            if ($roles !== [] && array_intersect($roles, (array) $exclusions['roles']) !== []) {
                return true;
            }
        }

        if (! empty($exclusions['headers']) && is_array($exclusions['headers'])) {
            $reqHeaders = (array) ($ctx->attributes['headers'] ?? []);
            foreach ($exclusions['headers'] as $name => $expected) {
                $key = strtolower((string) $name);
                $val = $reqHeaders[$key] ?? null;
                $actual = is_array($val) ? ($val[0] ?? null) : $val;
                if ($actual !== null && ($expected === '*' || (string) $actual === (string) $expected)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Fase PRE: periksa request sebelum controller.
     *
     * @param array<string, mixed> $overrides Override per-route/controller (profile, throttle, block, mode, detectors, bypass).
     */
    public function inspect(RequestContext $ctx, array $overrides = []): Decision
    {
        if (! empty($overrides['bypass']) || $this->isAllowed($ctx)) {
            return Decision::allow();
        }

        $resolved = $this->resolveProfileOverrides($ctx->path, $overrides);
        if (! empty($resolved['bypass'])) {
            return Decision::allow();
        }

        if ($this->store->has($this->blockKey($ctx->ip))) {
            return $this->log($ctx, new Decision(
                Action::Block,
                100,
                [new Signal('blocklist', 100, 'IP is blocked')],
            ));
        }

        // Pertahanan Berlapis (Defense-in-Depth): Cek blacklist snapshot cache tenant
        $tenant = $ctx->attributes['tenant'] ?? $this->currentTenant();
        if ($tenant && class_exists(\Illuminate\Support\Facades\Cache::class) && \Illuminate\Support\Facades\Cache::getFacadeRoot() !== null) {
            $bannedKey = "guard:{$tenant}:banned_ips";
            $bannedIps = (array) \Illuminate\Support\Facades\Cache::get($bannedKey, []);
            if (! empty($bannedIps) && in_array($ctx->ip, $bannedIps, true)) {
                return $this->log($ctx, new Decision(
                    Action::Block,
                    100,
                    [new Signal('blocklist', 100, 'IP is in snapshot banned_ips')],
                ));
            }
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

        $inspectCtx = $this->stripExcludedFields($ctx);
        $allowedDetectors = $resolved['detectors'] ?? null;

        $signals = [];
        $enforcingSignals = [];
        foreach ($this->detectors as $detector) {
            if ($allowedDetectors !== null && ! $this->detectorMatchesFilter($detector, $allowedDetectors)) {
                continue;
            }

            $detectorMonitorOnly = $this->isDetectorMonitorOnly($detector, $resolved);
            foreach ($detector->inspect($inspectCtx) as $signal) {
                if ($allowedDetectors !== null && ! $this->signalMatchesFilter($signal->detector, $allowedDetectors)) {
                    continue;
                }
                $signals[] = $signal;
                if (! $detectorMonitorOnly && ! $this->isSignalMonitorOnly($signal->detector)) {
                    $enforcingSignals[] = $signal;
                }
            }
        }

        $score = $this->reputation($ctx) + $this->sum($enforcingSignals);
        $this->persist($ctx, $enforcingSignals);

        [$throttleAt, $blockAt] = [$resolved['throttle'], $resolved['block']];
        $effectiveMode = $resolved['mode'] ?? ($this->config['mode'] ?? 'monitor');

        if ($effectiveMode === 'monitor') {
            $action = Action::Allow;
        } else {
            $action = match (true) {
                $score >= $blockAt => Action::Block,
                $score >= $throttleAt => Action::Throttle,
                default => Action::Allow,
            };
        }

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
        if ($effectiveMode !== 'monitor' && $score >= $banThreshold && $ctx->userId !== null) {
            $this->evaluateUserPenalty($ctx, $score, implode('; ', $decision->reasons()), signals: $enforcingSignals);
        }

        // Evaluasi pemblokiran IP otomatis jika request diputuskan Block (Auto-Block IP)
        if ($effectiveMode !== 'monitor' && $action === Action::Block && $ctx->ip !== '' && $ctx->ip !== '127.0.0.1') {
            $this->evaluateIpBlock($ctx, $score, $blockAt, $enforcingSignals, $resolved['profile_name'] ?? null);
        }

        if ($this->onScoredCallback !== null) {
            ($this->onScoredCallback)($ctx, $decision);
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
        if ($this->onIncidentCallback !== null) {
            ($this->onIncidentCallback)($incident);
        }
    }

    public function block(string $ip, int $seconds, string $reason = 'Manual IP block', string $source = 'manual', int $score = 100): void
    {
        $this->store->put($this->blockKey($ip), 1, $seconds);

        $now = time();
        $record = new BanRecord(
            type: BanRecord::TYPE_IP,
            subject: $ip,
            reason: $reason,
            source: $source,
            score: $score,
            bannedAt: $now,
            expiresAt: $seconds > 0 ? $now + $seconds : null,
            ip: $ip,
        );

        if ($this->banRegistry !== null) {
            $this->banRegistry->record($record);
        }

        if ($this->onBanCallback !== null) {
            ($this->onBanCallback)($record);
        }

        if ($this->vulnerabilityStore !== null) {
            $this->recordVulnerability([
                'type' => 'ban.created',
                'ban_type' => BanRecord::TYPE_IP,
                'severity' => 'high',
                'score' => $score,
                'ip' => $ip,
                'subject' => $ip,
                'source' => $source,
                'reasons' => [$reason],
                'banned_at' => date('Y-m-d H:i:s', $now),
                'expires_at' => $record->expiresAt ? date('Y-m-d H:i:s', $record->expiresAt) : null,
                'timestamp' => date('Y-m-d H:i:s', $now),
            ]);
        }
    }

    public function unblock(string $ip, string $liftedBy = 'system', string $reason = 'Manual unblock'): void
    {
        $previous = $this->banRegistry?->find(BanRecord::TYPE_IP, $ip);

        $this->store->forget($this->blockKey($ip));
        $this->store->forget("score:ip:{$ip}");

        if ($this->banRegistry !== null) {
            $this->banRegistry->remove(BanRecord::TYPE_IP, $ip);
        }

        if ($this->onBanLiftedCallback !== null) {
            ($this->onBanLiftedCallback)(BanRecord::TYPE_IP, $ip, $liftedBy, $reason, $previous);
        }

        if ($this->vulnerabilityStore !== null) {
            $this->recordVulnerability([
                'type' => 'ban.lifted',
                'ban_type' => BanRecord::TYPE_IP,
                'severity' => 'info',
                'ip' => $ip,
                'subject' => $ip,
                'lifted_by' => $liftedBy,
                'reasons' => [$reason],
                'timestamp' => date('Y-m-d H:i:s'),
            ]);
        }
    }

    public function isBlocked(string $ip): bool
    {
        if ($this->store->has($this->blockKey($ip))) {
            return true;
        }

        // Jika skor reputasi IP saat ini mencapai atau melampaui ambang batas blokir
        $globalBlock = (int) ($this->config['thresholds']['block'] ?? 100);
        $strictBlock = (int) ($this->config['profiles']['strict']['block'] ?? 70);
        $minBlock = min($globalBlock, $strictBlock);

        return $this->scoreOf($ip) >= $minBlock;
    }

    public function hasExplicitBlock(string $ip): bool
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

    public function unbanUser(string|int $userId, string $liftedBy = 'system', string $reason = 'Manual unban'): void
    {
        $previous = $this->banRegistry?->find(BanRecord::TYPE_USER, (string) $userId);

        $this->store->forget("block:user:{$userId}");
        $this->store->forget("guard:user_banned:{$userId}");
        $this->store->forget("score:user:{$userId}");
        $this->store->forget("force_logout:user:{$userId}");

        if ($this->banRegistry !== null) {
            $this->banRegistry->remove(BanRecord::TYPE_USER, (string) $userId);
        }

        $ruleCaps = $this->config['user_ban']['rule_score_caps'] ?? [];
        foreach (array_keys($ruleCaps) as $ruleKey) {
            $this->store->forget("score:user:{$userId}:rule:{$ruleKey}");
        }

        if (class_exists(\Illuminate\Support\Facades\Cache::class) && \Illuminate\Support\Facades\Cache::getFacadeRoot() !== null) {
            try {
                \Illuminate\Support\Facades\Cache::forget("block:user:{$userId}");
                \Illuminate\Support\Facades\Cache::forget("guard:user_banned:{$userId}");
                \Illuminate\Support\Facades\Cache::forget("score:user:{$userId}");
                \Illuminate\Support\Facades\Cache::forget("force_logout:user:{$userId}");
            } catch (\Throwable) {
            }
        }

        if ($this->onBanLiftedCallback !== null) {
            ($this->onBanLiftedCallback)(BanRecord::TYPE_USER, (string) $userId, $liftedBy, $reason, $previous);
        }

        if ($this->vulnerabilityStore !== null) {
            $this->recordVulnerability([
                'type' => 'ban.lifted',
                'ban_type' => BanRecord::TYPE_USER,
                'severity' => 'info',
                'user_id' => (string) $userId,
                'subject' => (string) $userId,
                'lifted_by' => $liftedBy,
                'reasons' => [$reason],
                'timestamp' => date('Y-m-d H:i:s'),
            ]);
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

    /** @return array<string, BanRecord> */
    public function bans(?string $type = null): array
    {
        if ($this->banRegistry === null) {
            return [];
        }

        $all = $this->banRegistry->all();
        if ($type !== null && $type !== '') {
            $all = array_filter($all, fn (BanRecord $b) => $b->type === $type);
        }

        return $all;
    }

    public function findBan(string $type, string|int $subject): ?BanRecord
    {
        return $this->banRegistry?->find($type, (string) $subject);
    }

    /**
     * Bersihkan seluruh daftar ban aktif (IP dan/atau User) sekaligus,
     * mereset skor reputasi, memicu event BanLifted, dan mengosongkan indeks BanRegistry.
     *
     * @return int Jumlah ban yang berhasil dibersihkan
     */
    public function clearBans(?string $type = null, string $liftedBy = 'system', string $reason = 'Bulk clear'): int
    {
        $targets = $this->bans($type);
        $cleared = 0;

        foreach ($targets as $ban) {
            if ($ban->type === BanRecord::TYPE_IP) {
                $this->unblock($ban->subject, $liftedBy, $reason);
                $cleared++;
            } elseif ($ban->type === BanRecord::TYPE_USER) {
                $this->unbanUser($ban->subject, $liftedBy, $reason);
                $cleared++;
            }
        }

        if ($this->banRegistry !== null) {
            $extra = $this->banRegistry->clear($type);
            if ($cleared === 0 && $extra > 0) {
                $cleared = $extra;
            }
        }

        return $cleared;
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

        if ($this->banRegistry !== null) {
            $now = time();
            $label = is_object($userObject) ? ($userObject->username ?? $userObject->email ?? null) : null;
            $this->banRegistry->record(new BanRecord(
                type: BanRecord::TYPE_USER,
                subject: (string) $userId,
                reason: $reason,
                source: 'user_ban',
                score: $score,
                bannedAt: $now,
                expiresAt: $ttl > 0 ? $now + $ttl : null,
                ip: $ctx->ip ?: null,
                meta: array_filter(['label' => $label, 'path' => $ctx->path]),
            ));
        }

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

    private function evaluateIpBlock(
        RequestContext $ctx,
        int $score,
        int $blockAt,
        array $signals = [],
        ?string $profileName = null
    ): void {
        if (! ($this->config['ip_ban']['enabled'] ?? true)) {
            return;
        }

        $ip = $ctx->ip;
        if ($ip === '' || $ip === '127.0.0.1') {
            return;
        }

        // Jika pemblokiran ini hanya berasal dari sinyal ephemeral tanpa persistensi dan reputasi IP sendiri masih 0
        // (contoh: brute force pair pada login), jangan hard-ban IP secara global agar path lain tetap diizinkan
        $hasPersistentSignal = false;
        foreach ($signals as $s) {
            if ($s->persist) {
                $hasPersistentSignal = true;
                break;
            }
        }
        $ipReputation = $this->store->count("score:ip:{$ip}");

        // Rekam ban jika IP memang memiliki skor reputasi persisten >= blockAt ATAU ada sinyal persisten
        if ($ipReputation < $blockAt && ! $hasPersistentSignal) {
            return;
        }

        $ttl = (int) ($this->config['ip_ban']['duration'] ?? $this->config['reputation_ttl'] ?? 1800);

        // Ekstraksi nama detektor pemicu
        $detectors = array_unique(array_filter(array_map(fn (Signal $s) => $s->detector, $signals)));
        $source = ! empty($detectors) ? implode(',', $detectors) : 'reputation';

        // Susun deskripsi alasan
        $signalReasons = array_filter(array_map(fn (Signal $s) => $s->reason, $signals));
        $reason = ! empty($signalReasons)
            ? implode('; ', $signalReasons)
            : "Skor reputasi ({$score}) mencapai batas pemblokiran ({$blockAt})";

        if ($profileName) {
            $reason .= " [profil: {$profileName}, path: '{$ctx->path}']";
        }

        $this->block(
            ip: $ip,
            seconds: $ttl,
            reason: $reason,
            source: $source,
            score: $score
        );
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
        $resolved = $this->resolveProfileOverrides($path, []);

        return [$resolved['throttle'], $resolved['block']];
    }

    /**
     * Gabungkan preset/profile berdasarkan path dan override per-route/controller.
     *
     * @param array<string, mixed> $overrides
     * @return array{throttle:int, block:int, mode:?string, detectors:?array, bypass:bool}
     */
    public function resolveProfileOverrides(string $path, array $overrides = []): array
    {
        $base = $this->config['thresholds'] ?? ['throttle' => 50, 'block' => 100];
        $presets = $this->builtInPresets();
        $profiles = array_replace_recursive($presets, $this->config['profiles'] ?? []);

        $matched = [];
        $profileName = null;
        if (! empty($overrides['profile']) && isset($profiles[$overrides['profile']])) {
            $matched = (array) $profiles[$overrides['profile']];
            $profileName = (string) $overrides['profile'];
        } else {
            foreach ($this->config['profiles'] ?? [] as $name => $profile) {
                if (! empty($profile['paths']) && PathMatcher::matches((array) $profile['paths'], $path) !== null) {
                    $matched = (array) $profile;
                    $profileName = is_string($name) ? $name : null;
                    break;
                }
            }
        }

        $merged = array_merge($base, $matched, array_filter($overrides, fn ($v) => $v !== null));

        return [
            'throttle' => (int) ($merged['throttle'] ?? 50),
            'block' => (int) ($merged['block'] ?? 100),
            'mode' => isset($merged['mode']) ? (string) $merged['mode'] : null,
            'detectors' => isset($merged['detectors']) && is_array($merged['detectors']) ? $merged['detectors'] : null,
            'bypass' => ! empty($merged['bypass']),
            'profile_name' => $profileName,
        ];
    }

    /** @return array<string, array<string, mixed>> */
    private function builtInPresets(): array
    {
        return [
            'strict' => ['throttle' => 30, 'block' => 70, 'mode' => 'enforce'],
            'balanced' => ['throttle' => 50, 'block' => 100, 'mode' => 'enforce'],
            'monitor' => ['throttle' => 50, 'block' => 100, 'mode' => 'monitor'],
        ];
    }

    private function stripExcludedFields(RequestContext $ctx): RequestContext
    {
        $fields = (array) ($this->config['exclusions']['fields'] ?? []);
        $inputs = $ctx->attributes['inputs'] ?? null;
        if ($fields === [] || ! is_array($inputs) || $inputs === []) {
            return $ctx;
        }

        $filtered = $this->filterFieldsRecursive($inputs, $fields);
        $attrs = $ctx->attributes;
        $attrs['inputs'] = $filtered;

        return new RequestContext(
            ip: $ctx->ip,
            method: $ctx->method,
            path: $ctx->path,
            userAgent: $ctx->userAgent,
            routeName: $ctx->routeName,
            userId: $ctx->userId,
            identifier: $ctx->identifier,
            attributes: $attrs,
        );
    }

    /**
     * @param array<string|int, mixed> $inputs
     * @param string[] $excludedPatterns
     * @return array<string|int, mixed>
     */
    private function filterFieldsRecursive(array $inputs, array $excludedPatterns): array
    {
        $out = [];
        foreach ($inputs as $key => $val) {
            $matched = false;
            foreach ($excludedPatterns as $pattern) {
                if (fnmatch((string) $pattern, (string) $key, FNM_CASEFOLD)) {
                    $matched = true;
                    break;
                }
            }
            if ($matched) {
                continue;
            }
            $out[$key] = is_array($val) ? $this->filterFieldsRecursive($val, $excludedPatterns) : $val;
        }

        return $out;
    }

    /** @param string[] $allowed */
    private function detectorMatchesFilter(Detector $detector, array $allowed): bool
    {
        $detName = strtolower($detector->name());
        $short = strtolower((string) preg_replace('/Detector$/', '', (new \ReflectionClass($detector))->getShortName()));

        foreach ($allowed as $name) {
            $n = strtolower(trim((string) $name));
            if ($n === $detName || $n === $short || ($n === 'waf' && in_array($detName, ['honeypot', 'path_traversal', 'malicious_payload', 'parameter_tampering', 'anomaly'], true))) {
                return true;
            }
        }

        return false;
    }

    /** @param string[] $allowed */
    private function signalMatchesFilter(string $signalDetector, array $allowed): bool
    {
        foreach ($allowed as $name) {
            $n = strtolower(trim((string) $name));
            if ($n === strtolower($signalDetector) || $n === 'waf') {
                return true;
            }
        }

        return true;
    }

    /** @param array<string, mixed> $resolved */
    private function isDetectorMonitorOnly(Detector $detector, array $resolved): bool
    {
        if (($resolved['mode'] ?? null) === 'monitor') {
            return true;
        }
        $detCfg = $this->config['detectors'][$detector->name()] ?? [];

        return ($detCfg['mode'] ?? null) === 'monitor' || ! empty($detCfg['monitor_only']);
    }

    private function isSignalMonitorOnly(string $detectorName): bool
    {
        $detCfg = $this->config['detectors'][$detectorName] ?? [];
        if (($detCfg['mode'] ?? null) === 'monitor' || ! empty($detCfg['monitor_only'])) {
            return true;
        }
        $ruleCfg = $this->config['rules'][$detectorName] ?? [];

        return ($ruleCfg['mode'] ?? null) === 'monitor' || ! empty($ruleCfg['monitor_only']);
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
