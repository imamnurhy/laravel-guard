<?php
/**
 * Smoke test core tanpa Laravel/composer: php tests/smoke.php
 */
spl_autoload_register(function ($c) {
    if (str_starts_with($c, 'AppGuard\\')) {
        require __DIR__ . '/../src/' . str_replace('\\', '/', substr($c, 9)) . '.php';
    }
}, true, true);

if (! class_exists(\Illuminate\Console\Command::class)) {
    eval('namespace Illuminate\Console; class Command {}');
}

function env($k, $d = null) { return $d; }
function storage_path($p = '') { return sys_get_temp_dir() . '/' . $p; }

use AppGuard\Attributes\GuardProfile;
use AppGuard\Core\{Action, BanRecord, Guard, RequestContext, Signal};
use AppGuard\Core\Contracts\Detector;
use AppGuard\Core\Detectors\{
    AnomalyDetector,
    BruteForceDetector,
    DeniedAccessDetector,
    HoneypotDetector,
    MaliciousPayloadDetector,
    ParameterTamperingDetector,
    PathTraversalDetector
};
use AppGuard\Core\Stores\{ArrayBanRegistry, ArrayStore, ArrayVulnerabilityStore, NullVulnerabilityStore};
use AppGuard\Core\Contracts\VulnerabilityStore;
use AppGuard\Stores\{CacheVulnerabilityStore, JsonFileVulnerabilityStore, RedisVulnerabilityStore};
use AppGuard\Console\ShipTelemetryCommand;

class MockVulnerabilityStore implements VulnerabilityStore
{
    public array $recorded = [];
    public function recordExposed(array $incident): void { $this->recorded[] = $incident; }
    public function getExposedIncidents(int $limit = 100): array { return array_reverse(array_slice($this->recorded, -$limit)); }
    public function peekBatch(int $limit = 100): array { return array_values(array_slice($this->recorded, 0, $limit)); }
    public function acknowledgeBatch(int $count): void { $this->recorded = array_values(array_slice($this->recorded, $count)); }
    public function pullBatch(int $limit = 100): array {
        $b = $this->peekBatch($limit);
        $this->acknowledgeBatch(count($b));
        return $b;
    }
    public function count(): int { return count($this->recorded); }
    public function clear(): void { $this->recorded = []; }
}

$cfg = require __DIR__ . '/../config/guard.php';
$cfg['mode'] = 'enforce';
$cfg['enabled'] = true;
$store = new ArrayStore();
$banRegistry = new ArrayBanRegistry();
$vulnStore = new MockVulnerabilityStore();
$bf = new BruteForceDetector($store, $cfg['detectors']['brute_force']);

$bannedUsers = [];
$loggedOutUsers = [];
$guard = new Guard($store, [
    new HoneypotDetector($cfg['detectors']['honeypot']),
    $bf,
    new DeniedAccessDetector($store, $cfg['detectors']['denied_access']),
    new PathTraversalDetector($cfg['detectors']['path_traversal']),
    new MaliciousPayloadDetector($cfg['detectors']['malicious_payload']),
    new ParameterTamperingDetector($cfg['detectors']['parameter_tampering']),
    new AnomalyDetector($store, $cfg['detectors']['anomaly']),
], $cfg, null, $vulnStore, $banRegistry);

$guard->setOnUserBanned(function ($user, $score, $reason) use (&$bannedUsers) {
    $bannedUsers[] = ['user' => $user, 'score' => $score, 'reason' => $reason];
});
$guard->setOnUserForceLoggedOut(function ($user, $score, $reason) use (&$loggedOutUsers) {
    $loggedOutUsers[] = ['user' => $user, 'score' => $score, 'reason' => $reason];
});

$fail = 0;
function check(string $name, bool $ok) { global $fail; echo ($ok ? 'PASS' : 'FAIL') . "  $name\n"; if (!$ok) $fail++; }
$ctx = fn ($path, $ip = '1.1.1.1', $id = null, $user = null, $method = 'GET', $attrs = []) =>
    new RequestContext($ip, $method, $path, 'ua', null, $user, $id, $attrs);

// 1. Normal
check('normal request allowed', $guard->inspect($ctx('/orders'))->action === Action::Allow);

// 2. Honeypot
check('honeypot blocks', $guard->inspect($ctx('/.env', '2.2.2.2'))->action === Action::Block);
check('reputation sticks to normal path', $guard->inspect($ctx('/orders', '2.2.2.2'))->action === Action::Block);
check('other IP unaffected', $guard->inspect($ctx('/orders', '3.3.3.3'))->action === Action::Allow);

// 3. Brute force pair
for ($i = 0; $i < 5; $i++) $bf->recordFailure('4.4.4.4', 'Bob@Mail.com');
foreach (['8.8.8.1','8.8.8.2','8.8.8.3'] as $other) $bf->recordFailure($other, 'bob@mail.com');
check('pair brute force blocks on login', $guard->inspect($ctx('/login', '4.4.4.4', 'bob@mail.com'))->action === Action::Block);
check('same IP other path ok', $guard->inspect($ctx('/orders', '4.4.4.4'))->action === Action::Allow);
check('other IP same account only throttle-level', $guard->inspect($ctx('/login', '5.5.5.5', 'bob@mail.com'))->score === 60);

// 4. Path Traversal
check('path traversal in URL blocked', $guard->inspect($ctx('/files/../../etc/passwd', '11.11.11.11'))->score >= 50);
check('path traversal in parameter blocked', $guard->inspect($ctx('/download', '11.11.11.12', null, null, 'GET', [
    'inputs' => ['file' => '../../../secret.txt']
]))->score >= 50);

// 5. Malicious Payload (SQLi & XSS)
check('SQL injection detected', $guard->inspect($ctx('/search', '12.12.12.12', null, null, 'GET', [
    'inputs' => ['q' => "' union select null, username, password from users--"]
]))->score >= 100);

check('nested SQL injection detected', $guard->inspect($ctx('/filter', '12.12.12.13', null, null, 'POST', [
    'inputs' => ['filter' => ['keyword' => "' union select null, username, password from users--"]]
]))->score >= 100);

check('XSS payload detected', $guard->inspect($ctx('/comment', '13.13.13.13', null, null, 'POST', [
    'inputs' => ['text' => "<script>alert('xss')</script>"]
]))->score >= 50);

// 6. Parameter Tampering
check('parameter tampering (is_admin injection) detected', $guard->inspect($ctx('/profile/update', '14.14.14.14', null, '101', 'POST', [
    'inputs' => ['is_admin' => 1, 'nama' => 'Hacker']
]))->score >= 35);

check('nested parameter tampering (user[is_admin]) detected', $guard->inspect($ctx('/profile/update', '14.14.14.15', null, '102', 'POST', [
    'inputs' => ['user' => ['is_admin' => 1]]
]))->score >= 35);

// 7. Anomaly Detector: Valid JSON auto-bypass & Wildcard Safe Fields
$jsonPayload = json_encode([
    'rtdr_data' => [
        'polygon' => 'POLYGON((106.68 -6.29, 106.69 -6.30, 106.70 -6.31, 106.68 -6.29))',
        'attributes' => ['code' => 'RTDR_2026_X99', 'verified' => true, 'timestamp' => '2026-10-16T12:00:00Z'],
        'meta' => 'Random long description with lots of varied symbols and characters to exceed 150 characters length easily.'
    ]
]);
check('valid JSON string payload is auto-bypassed from high entropy', $guard->inspect($ctx('/perizinan/store', '16.16.16.16', null, '201', 'POST', [
    'inputs' => ['rtdr_data' => $jsonPayload]
]))->score === 0);

$anomalyDetectorWithWildcard = new AnomalyDetector($store, [
    'enabled' => true,
    'safe_fields' => ['*alamat*', 'rtdr_data'],
    'entropy_threshold' => 4.8,
    'entropy_min_length' => 150,
]);
$guardWildcard = new Guard($store, [$anomalyDetectorWithWildcard], $cfg);
$longAddress = 'Jalan Pahlawan Revolusi No. 45 RT 003 / RW 012 Kelurahan Pondok Jagung Timur Kecamatan Serpong Utara Gedung Menara Hijau Lantai 8 Tangerang Selatan Banten 15326';
check('wildcard safe_fields (*alamat*) ignores perusahaan_alamat', $guardWildcard->inspect($ctx('/perizinan/store', '17.17.17.17', null, '202', 'POST', [
    'inputs' => ['perusahaan_alamat' => $longAddress]
]))->score === 0);

// 8. Tiered Defense: Non-critical repeated violation triggers Soft Force-Logout (NOT Hard Ban)
$userNonCritical = (object)['id' => 999, 'username' => 'test_pemohon'];
$guard->recordViolation($userNonCritical, 'idor', 25, 'Akses data #1');
$guard->recordViolation($userNonCritical, 'idor', 25, 'Akses data #2');
$guard->recordViolation($userNonCritical, 'idor', 25, 'Akses data #3');
check('user not yet logged out at 75 points', count($loggedOutUsers) === 0 && count($bannedUsers) === 0);

$guard->recordViolation($userNonCritical, 'idor', 25, 'Akses data #4');
check('user force logout triggered at 100 points for non-critical violation', count($loggedOutUsers) === 1 && $loggedOutUsers[0]['user']->id === 999);
check('user is NOT banned in database for non-critical violation', count($bannedUsers) === 0);

// 9. Tiered Defense: Critical exploit (SQLi) triggers Hard Ban
$userCritical = (object)['id' => 888, 'username' => 'sqli_attacker'];
$guard->recordViolation($userCritical, 'sqli', 100, 'SQL Injection in login form');
check('user hard-banned triggered for critical exploit (SQLi)', count($bannedUsers) === 1 && $bannedUsers[0]['user']->id === 888);
check('banned user inspection is blocked', $guard->inspect($ctx('/dashboard', '18.18.18.18', null, '888'))->action === Action::Block);

// 10. Rule Score Cap test: high_entropy cap at 35 points
$userCap = (object)['id' => 777, 'username' => 'entropy_repeater'];
$guard->recordViolation($userCap, 'high_entropy', 35, 'Keacakan tinggi #1');
$guard->recordViolation($userCap, 'high_entropy', 35, 'Keacakan tinggi #2');
$guard->recordViolation($userCap, 'high_entropy', 35, 'Keacakan tinggi #3');
check('rule score cap prevents single anomaly from accumulating past cap (score is 35, not 105)', $guard->scoreOfUser(777) === 35);
check('user not banned due to rule score cap', count(array_filter($bannedUsers, fn($b) => $b['user']->id === 777)) === 0);

// 11. Allowlist (Exact IP & CIDR Subnet) & Manual unblock
$cfg2 = $cfg;
$cfg2['allowlist'] = ['9.9.9.9', '192.168.1.0/24'];
$g2 = new Guard($store, [new HoneypotDetector($cfg['detectors']['honeypot'])], $cfg2);
check('exact IP allowlist bypass', $g2->inspect($ctx('/.env', '9.9.9.9'))->action === Action::Allow);
check('CIDR subnet IP allowlist bypass', $g2->inspect($ctx('/.env', '192.168.1.45'))->action === Action::Allow);
check('non-allowlist IP inspected normally', $g2->inspect($ctx('/.env', '88.88.88.88'))->action === Action::Block);

$guard->block('7.7.7.7', 60);
check('manual block', $guard->inspect($ctx('/', '7.7.7.7'))->action === Action::Block);
$guard->unblock('7.7.7.7');
check('unblock', $guard->inspect($ctx('/', '7.7.7.7'))->action === Action::Allow);

// 12. unbanUser & isUserBanned tests
check('user 888 is initially banned', $guard->isUserBanned(888) === true);
check('user 888 recorded in BanRegistry', $guard->findBan(BanRecord::TYPE_USER, 888) !== null);
$guard->unbanUser(888);
check('user 888 is not banned after unbanUser', $guard->isUserBanned(888) === false);
check('user 888 removed from BanRegistry after unbanUser', $guard->findBan(BanRecord::TYPE_USER, 888) === null);
check('user 888 score is reset to 0', $guard->scoreOfUser(888) === 0);
check('user 888 inspection is allowed after unban', $guard->inspect($ctx('/dashboard', '18.18.18.18', null, '888'))->action === Action::Allow);

// 13. BanRegistry index: block, list, filter by type, unblock
$liftedEvents = [];
$banEvents = [];
$guard->onBan(function (BanRecord $b) use (&$banEvents) { $banEvents[] = $b; });
$guard->onBanLifted(function (string $type, string $sub, string $by) use (&$liftedEvents) { $liftedEvents[] = "{$type}:{$sub}:{$by}"; });

$guard->block('203.0.113.50', 300, 'Brute force SSH', 'manual', 100);
$ipBan = $guard->findBan(BanRecord::TYPE_IP, '203.0.113.50');
check('IP block recorded in BanRegistry with metadata', $ipBan !== null && $ipBan->reason === 'Brute force SSH' && ($ipBan->remaining() ?? 0) > 0);
check('onBan callback fired for IP block', count($banEvents) === 1 && $banEvents[0]->subject === '203.0.113.50');
check('Guard::bans filters by type IP', isset($guard->bans(BanRecord::TYPE_IP)['ip:203.0.113.50']));
$guard->unblock('203.0.113.50', 'cli_admin', 'False positive');
check('IP unblock removes entry from BanRegistry', $guard->findBan(BanRecord::TYPE_IP, '203.0.113.50') === null);
check('onBanLifted callback fired with liftedBy', in_array('ip:203.0.113.50:cli_admin', $liftedEvents, true));

// 14. Profile overrides, monitor-only mode, detector filtering, and GuardProfile attribute
$attr = new GuardProfile('strict', block: 40, mode: 'monitor', detectors: ['honeypot']);
$ov = $attr->toOverrides();
check('GuardProfile attribute converts to overrides', $ov['profile'] === 'strict' && $ov['block'] === 40 && $ov['mode'] === 'monitor');

$monDecision = $guard->inspect($ctx('/.env', '198.51.100.77'), ['mode' => 'monitor']);
check('per-route monitor override detects signal but allows request', $monDecision->action === Action::Allow && count($monDecision->signals) > 0);

$onlyHoneypot = $guard->inspect($ctx('/search', '198.51.100.78', null, null, 'GET', [
    'inputs' => ['q' => "' union select 1,2,3--"]
]), ['detectors' => ['honeypot']]);
check('detector filter skips non-matching MaliciousPayloadDetector', $onlyHoneypot->action === Action::Allow && $onlyHoneypot->score === 0);

$bypassDecision = $guard->inspect($ctx('/.env', '198.51.100.79'), ['bypass' => true]);
check('bypass override skips all inspection', $bypassDecision->action === Action::Allow && $bypassDecision->score === 0);

// 15. Multi-dimensional exclusions (paths, fields, users, roles, headers) + custom detector + monitor-only per detector
$cfgEx = $cfg;
$cfgEx['exclusions'] = [
    'paths' => ['/health*'],
    'fields' => ['raw_sql_note'],
    'users' => ['vip-1'],
    'roles' => ['superadmin'],
    'headers' => ['x-probe' => 'ok'],
];
$cfgEx['detectors']['honeypot']['monitor_only'] = true;
$gEx = new Guard(new ArrayStore(), [
    new HoneypotDetector($cfgEx['detectors']['honeypot']),
    new MaliciousPayloadDetector($cfgEx['detectors']['malicious_payload']),
], $cfgEx);

check('path exclusion bypasses /.env under /health*', $gEx->inspect($ctx('/health/check', '198.51.100.80'))->action === Action::Allow);
check('field exclusion strips raw_sql_note from SQLi inspection', $gEx->inspect($ctx('/save', '198.51.100.81', null, null, 'POST', [
    'inputs' => ['raw_sql_note' => "' union select username, password from users--"]
]))->score === 0);
check('user exclusion bypasses vip-1', $gEx->inspect($ctx('/.env', '198.51.100.82', null, 'vip-1'))->action === Action::Allow);
check('role exclusion bypasses superadmin', $gEx->inspect($ctx('/.env', '198.51.100.83', null, '500', 'GET', ['roles' => ['superadmin']]))->action === Action::Allow);
check('header exclusion bypasses matching header', $gEx->inspect($ctx('/.env', '198.51.100.84', null, null, 'GET', ['headers' => ['x-probe' => ['ok']]]))->action === Action::Allow);
check('per-detector monitor_only records signal without blocking score', $gEx->inspect($ctx('/.env', '198.51.100.85'))->action === Action::Allow);

$customDetector = new class implements Detector {
    public function name(): string { return 'custom_trap'; }
    public function inspect(RequestContext $context): array {
        return $context->path === '/custom-trap' ? [new Signal('custom_trap', 100, 'Custom trap hit')] : [];
    }
    public function observe(RequestContext $context, int $status): array { return []; }
};
$gEx->addDetector($customDetector);
check('pluggable addDetector blocks on custom signal', $gEx->inspect($ctx('/custom-trap', '198.51.100.86'))->action === Action::Block);

// 16. Pluggable VulnerabilityStore drivers (Array & Null)
$arrVuln = new ArrayVulnerabilityStore();
$arrVuln->recordExposed(['type' => 'test']);
check('ArrayVulnerabilityStore stores and retrieves incidents', count($arrVuln->getExposedIncidents()) === 1);
$nullVuln = new NullVulnerabilityStore();
$nullVuln->recordExposed(['type' => 'ignored']);
// 17. Auto-Record IP Block on Reputation Threshold & BanRegistry Visibility
$testIp = '203.0.113.99';
$store->hit("score:ip:{$testIp}", 1800, 70);
check('IP with score 70 is flagged by isBlocked', $guard->isBlocked($testIp));
$strictInspect = $guard->inspect($ctx('/login', $testIp));
check('IP with score 70 is blocked on strict /login path', $strictInspect->action === Action::Block);
$autoBanRecord = $guard->findBan(BanRecord::TYPE_IP, $testIp);
check('IP with score 70 on strict path is auto-recorded in BanRegistry', $autoBanRecord !== null);
check('auto-recorded IP ban has correct score 70', ($autoBanRecord?->score ?? 0) === 70);
check('Guard::hasExplicitBlock is true after auto-record', $guard->hasExplicitBlock($testIp));
$guard->unblock($testIp);
check('IP score is reset to 0 after unblock', $guard->scoreOf($testIp) === 0);
check('IP is no longer blocked after unblock', ! $guard->isBlocked($testIp));
check('IP removed from BanRegistry after unblock', $guard->findBan(BanRecord::TYPE_IP, $testIp) === null);

// 18. Multi-driver Telemetry Store (JsonFile, Redis, Cache, Array) + ShipTelemetry batch queue
$tmpJsonlPath = sys_get_temp_dir() . '/guard_test_' . uniqid() . '.jsonl';
$jsonStore = new JsonFileVulnerabilityStore($tmpJsonlPath, maxItems: 3);
$jsonStore->recordExposed(['type' => 'sqli', 'ip' => '10.0.0.1', 'score' => 100]);
$jsonStore->recordExposed(['type' => 'xss', 'ip' => '10.0.0.2', 'score' => 50]);
$jsonStore->recordExposed(['type' => 'idor', 'ip' => '10.0.0.3', 'score' => 25]);
$jsonStore->recordExposed(['type' => 'honeypot', 'ip' => '10.0.0.4', 'score' => 100]);
check('JsonFileVulnerabilityStore enforces maxItems cap (3 items)', $jsonStore->count() === 3);
$peekJson = $jsonStore->peekBatch(2);
check('JsonFileVulnerabilityStore peekBatch returns oldest FIFO items without removing', count($peekJson) === 2 && $peekJson[0]['ip'] === '10.0.0.2' && $jsonStore->count() === 3);
$jsonStore->acknowledgeBatch(2);
check('JsonFileVulnerabilityStore acknowledgeBatch removes shipped items', $jsonStore->count() === 1 && $jsonStore->peekBatch(5)[0]['ip'] === '10.0.0.4');
$jsonStore->clear();
check('JsonFileVulnerabilityStore clear empties file buffer', $jsonStore->count() === 0);
@unlink($tmpJsonlPath);

// Mock Redis connection (RPUSH, LRANGE, LTRIM, LLEN, DEL)
$fakeRedis = new class {
    public array $lists = [];
    public function rpush(string $k, string $v): int { $this->lists[$k][] = $v; return count($this->lists[$k]); }
    public function lrange(string $k, int $start, int $stop): array {
        $list = $this->lists[$k] ?? [];
        $len = count($list);
        if ($len === 0) return [];
        $s = $start < 0 ? max(0, $len + $start) : $start;
        $e = $stop < 0 ? $len + $stop : min($len - 1, $stop);
        if ($s > $e || $s >= $len) return [];
        return array_slice($list, $s, $e - $s + 1);
    }
    public function ltrim(string $k, int $start, int $stop): void {
        $this->lists[$k] = $this->lrange($k, $start, $stop);
    }
    public function llen(string $k): int { return count($this->lists[$k] ?? []); }
    public function del(string $k): void { unset($this->lists[$k]); }
};
$redisStore = new RedisVulnerabilityStore($fakeRedis, 'guard:telemetry:test', maxItems: 3);
$redisStore->recordExposed(['type' => 'sqli', 'ip' => '192.0.2.1', 'score' => 100]);
$redisStore->recordExposed(['type' => 'xss', 'ip' => '192.0.2.2', 'score' => 50]);
$redisStore->recordExposed(['type' => 'idor', 'ip' => '192.0.2.3', 'score' => 25]);
$redisStore->recordExposed(['type' => 'fuzz', 'ip' => '192.0.2.4', 'score' => 50]);
check('RedisVulnerabilityStore enforces maxItems via LTRIM', $redisStore->count() === 3);
check('RedisVulnerabilityStore getExposedIncidents returns newest first', $redisStore->getExposedIncidents(1)[0]['ip'] === '192.0.2.4');
$redisPeek = $redisStore->peekBatch(2);
$formattedBatch = ShipTelemetryCommand::formatBatch($redisPeek);
check('ShipTelemetryCommand::formatBatch formats Redis telemetry batch accurately', count($formattedBatch) === 2 && $formattedBatch[0]['ip_address'] === '192.0.2.2' && $formattedBatch[0]['violation_type'] === 'xss');
$redisStore->acknowledgeBatch(2);
check('RedisVulnerabilityStore acknowledgeBatch trims shipped records', $redisStore->count() === 1 && $redisStore->peekBatch(1)[0]['ip'] === '192.0.2.4');
$pulledRedis = $redisStore->pullBatch(5);
check('RedisVulnerabilityStore pullBatch fetches and empties remaining queue', count($pulledRedis) === 1 && $redisStore->count() === 0);

// Mock Cache Repository (get, put, forget)
$fakeCache = new class {
    public array $data = [];
    public function get(string $k, mixed $default = null): mixed { return $this->data[$k] ?? $default; }
    public function put(string $k, mixed $v, int $ttl = 0): bool { $this->data[$k] = $v; return true; }
    public function forget(string $k): bool { unset($this->data[$k]); return true; }
};
$cacheVulnStore = new CacheVulnerabilityStore($fakeCache, 'guard:telemetry:cache', maxItems: 2, ttl: 3600);
$cacheVulnStore->recordExposed(['type' => 'honeypot', 'ip' => '198.51.100.1', 'score' => 100]);
$cacheVulnStore->recordExposed(['type' => 'sqli', 'ip' => '198.51.100.2', 'score' => 100]);
$cacheVulnStore->recordExposed(['type' => 'xss', 'ip' => '198.51.100.3', 'score' => 50]);
check('CacheVulnerabilityStore enforces maxItems cap (2 items)', $cacheVulnStore->count() === 2);
$cachePulled = $cacheVulnStore->pullBatch(1);
check('CacheVulnerabilityStore pullBatch pops oldest item and retains remainder', count($cachePulled) === 1 && $cachePulled[0]['ip'] === '198.51.100.2' && $cacheVulnStore->count() === 1);
$cacheVulnStore->clear();
check('CacheVulnerabilityStore clear removes key from cache', $cacheVulnStore->count() === 0);

// 19. Bulk Clear / Flush All Bans (Guard::clearBans & BanRegistry::clear)
$guard->clearBans(null, 'cli_test', 'Reset previous test bans');
check('clearBans resets all prior test bans to 0', count($guard->bans()) === 0);

$guard->block('203.0.113.101', 600, 'Bulk test IP 1');
$guard->block('203.0.113.102', 600, 'Bulk test IP 2');
$guard->recordViolation((object)['id' => 555, 'username' => 'bulk_user'], 'sqli', 100, 'Bulk test user SQLi');
check('3 active bans (2 IP + 1 User) registered before clearBans', count($guard->bans()) === 3);

$ipClearedCount = $guard->clearBans(BanRecord::TYPE_IP, 'cli_test', 'Clear IP only');
check('clearBans(TYPE_IP) clears 2 IP bans and leaves 1 user ban', $ipClearedCount === 2 && count($guard->bans()) === 1 && $guard->isUserBanned(555));
check('cleared IPs are no longer blocked', ! $guard->isBlocked('203.0.113.101') && ! $guard->isBlocked('203.0.113.102'));

$guard->block('203.0.113.103', 600, 'Bulk test IP 3');
$allClearedCount = $guard->clearBans(null, 'cli_test', 'Clear all bans');
check('clearBans(null) clears all remaining IP and user bans', $allClearedCount === 2 && count($guard->bans()) === 0);
check('user 555 is unbanned and score reset after clearBans', ! $guard->isUserBanned(555) && $guard->scoreOfUser(555) === 0);

// 20. Built-in Security Response Views
$blockedView = file_get_contents(__DIR__ . '/../resources/views/blocked.blade.php');
$throttledView = file_get_contents(__DIR__ . '/../resources/views/throttled.blade.php');
check('blocked view template exists and contains security card & 403', str_contains($blockedView, '403') && str_contains($blockedView, 'Akses Anda Ditahan'));
check('throttled view template exists and contains countdown timer & 429', str_contains($throttledView, '429') && str_contains($throttledView, 'countdown-timer'));

echo "\nSummary: " . ($fail === 0 ? "ALL TESTS PASSED ✅" : "{$fail} TESTS FAILED ❌") . "\n";
exit($fail ? 1 : 0);

