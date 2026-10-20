# 📖 Contoh Kode Detektor Keamanan Kustom (Custom Detector)

Berikut adalah contoh kode implementasi detector kustom untuk memperkaya perlindungan WAF pada aplikasi Anda.

---

## 🔍 1. Contoh: `SuspiciousScannerDetector` (Fase PRE)

Mendeteksi tool pemindaian kerentanan otomatis (*vulnerability scanners*) berdasarkan karakteristik header HTTP:

```php
namespace App\Security\Detectors;

use AppGuard\Core\Contracts\Detector;
use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

class SuspiciousScannerDetector implements Detector
{
    /**
     * Pola tanda tangan scanner otomatis populer
     */
    protected const SCANNER_SIGNATURES = [
        'sqlmap',
        'nikto',
        'acunetix',
        'gobuster',
        'dirbuster',
        'nmap',
        'wpscan',
        'masscan',
        'zgrab',
    ];

    public function name(): string
    {
        return 'scanner_tool';
    }

    public function phase(): string
    {
        return 'pre';
    }

    public function detect(RequestContext $context): ?Signal
    {
        $userAgent = strtolower($context->headers['user-agent'] ?? '');

        // 1. Periksa User-Agent kosong pada request selain browser biasa
        if (empty($userAgent)) {
            return new Signal(
                detector: $this->name(),
                score: 25,
                description: 'Request tanpa User-Agent terdeteksi',
                persistent: false
            );
        }

        // 2. Periksa apakah cocok dengan signature scanner
        foreach (self::SCANNER_SIGNATURES as $signature) {
            if (str_contains($userAgent, $signature)) {
                return new Signal(
                    detector: $this->name(),
                    score: 100, // Langsung blokir
                    description: "Terdeteksi alat scanner otomatis: {$signature}",
                    persistent: true
                );
            }
        }

        return null;
    }
}
```

---

## ⏱️ 2. Contoh: `BurstSubmissionDetector` (Fase PRE)

Mencegah serangan bot spam submission pada endpoint formulir publik yang sangat sensitif (misal: formulir pendaftaran atau klaim reward):

```php
namespace App\Security\Detectors;

use AppGuard\Core\Contracts\Detector;
use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;
use Illuminate\Support\Facades\Cache;

class BurstSubmissionDetector implements Detector
{
    public function name(): string
    {
        return 'burst_submission';
    }

    public function phase(): string
    {
        return 'pre';
    }

    public function detect(RequestContext $context): ?Signal
    {
        // Hanya pantau metode mutasi POST
        if ($context->method !== 'POST') {
            return null;
        }

        // Hanya pantau route registrasi atau submit
        if (!str_contains($context->path, '/register') && !str_contains($context->path, '/submit')) {
            return null;
        }

        $cacheKey = "burst:ip:{$context->ip}";
        $attempts = (int) Cache::get($cacheKey, 0);

        if ($attempts >= 5) {
            return new Signal(
                detector: $this->name(),
                score: 75,
                description: 'Frekuensi pengiriman formulir terlalu cepat (kemungkinan bot otomatis)',
                persistent: true
            );
        }

        Cache::put($cacheKey, $attempts + 1, now()->addSeconds(10));
        return null;
    }
}
```

---

## 🧪 3. Contoh Unit Test untuk Detektor Kustom

```php
namespace Tests\Unit\Security;

use App\Security\Detectors\SuspiciousScannerDetector;
use AppGuard\Core\RequestContext;
use PHPUnit\Framework\TestCase;

class SuspiciousScannerDetectorTest extends TestCase
{
    public function test_detects_sqlmap_scanner()
    {
        $detector = new SuspiciousScannerDetector();
        $context = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            path: '/users',
            headers: ['user-agent' => 'sqlmap/1.6#stable (https://sqlmap.org)'],
            query: [],
            body: [],
            userId: null
        );

        $signal = $detector->detect($context);

        $this->assertNotNull($signal);
        $this->assertEquals(100, $signal->score);
        $this->assertEquals('scanner_tool', $signal->detector);
    }

    public function test_allows_normal_browser()
    {
        $detector = new SuspiciousScannerDetector();
        $context = new RequestContext(
            ip: '127.0.0.1',
            method: 'GET',
            path: '/users',
            headers: ['user-agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'],
            query: [],
            body: [],
            userId: null
        );

        $signal = $detector->detect($context);
        $this->assertNull($signal);
    }
}
```
