<?php
/**
 * Smoke test core tanpa Laravel/composer: php tests/smoke.php
 */
spl_autoload_register(function ($c) {
    if (str_starts_with($c, 'AppGuard\\')) {
        require __DIR__ . '/../src/' . str_replace('\\', '/', substr($c, 9)) . '.php';
    }
});

function env($k, $d = null) { return $d; }
function storage_path($p = '') { return sys_get_temp_dir() . '/' . $p; }

use AppGuard\Core\{Action, Guard, RequestContext};
use AppGuard\Core\Detectors\{
    AnomalyDetector,
    BruteForceDetector,
    DeniedAccessDetector,
    HoneypotDetector,
    MaliciousPayloadDetector,
    ParameterTamperingDetector,
    PathTraversalDetector
};
use AppGuard\Core\Stores\ArrayStore;
use AppGuard\Core\Contracts\VulnerabilityStore;

class MockVulnerabilityStore implements VulnerabilityStore
{
    public array $recorded = [];
    public function recordExposed(array $incident): void { $this->recorded[] = $incident; }
    public function getExposedIncidents(int $limit = 100): array { return $this->recorded; }
}

$cfg = require __DIR__ . '/../config/guard.php';
$cfg['mode'] = 'enforce';
$cfg['enabled'] = true;
$store = new ArrayStore();
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
], $cfg, null, $vulnStore);

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

echo "\nSummary: " . ($fail === 0 ? "ALL TESTS PASSED ✅" : "{$fail} TESTS FAILED ❌") . "\n";
exit($fail ? 1 : 0);
