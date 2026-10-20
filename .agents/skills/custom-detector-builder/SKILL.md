---
name: custom-detector-builder
description: Panduan pembuatan dan registrasi detektor keamanan kustom baru berbasis kontrak AppGuard\Core\Contracts\Detector untuk mendeteksi ancaman spesifik domain aplikasi.
---

# 🛠️ Custom Detector Builder Skill

Skill ini memandu AI Assistant dan Pengembang dalam merancang, mengimplementasikan, dan meregistrasikan detektor keamanan kustom (*Custom Security Detector*) pada package `explorin/laravel-guard`.

---

## 📋 Langkah Pembuatan Detektor Kustom

### Langkah 1: Tentukan Fase Eksekusi
- **Fase PRE (`'pre'`)**: Jika ingin memeriksa request **sebelum** diproses controller (memeriksa headers, method, path, query params, form inputs, atau honeypot).
- **Fase POST (`'post'`)**: Jika ingin mengobservasi **setelah** controller merespons (memeriksa status code HTTP, ukuran output, frekuensi 404/403 berulang).

---

### Langkah 2: Implementasikan Kontrak `Detector`
Buat class di namespace aplikasi (contoh `App\Security\Detectors\MyCustomDetector`) yang mengimplementasikan `AppGuard\Core\Contracts\Detector`:

```php
namespace App\Security\Detectors;

use AppGuard\Core\Contracts\Detector;
use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

class MyCustomDetector implements Detector
{
    public function name(): string
    {
        return 'my_custom_detector';
    }

    public function phase(): string
    {
        return 'pre'; // atau 'post'
    }

    public function detect(RequestContext $context): ?Signal
    {
        // 1. Ambil data dari RequestContext
        $userAgent = $context->headers['user-agent'] ?? '';

        // 2. Evaluasi kondisi ancaman
        if (str_contains(strtolower($userAgent), 'sqlmap')) {
            return new Signal(
                detector: $this->name(),
                score: 100, // Bobot penalti
                description: "Percobaan scanning menggunakan tool otomatis (SQLMap)",
                persistent: true // Akumulasikan ke reputasi penyerang
            );
        }

        // 3. Kembalikan null jika request bersih
        return null;
    }
}
```

---

### Langkah 3: Daftarkan Detektor di `config/guard.php`
Buka file `config/guard.php` pada aplikasi host, lalu tambahkan class ke array `detectors`:

```php
'detectors' => [
    // Detektor bawaan...
    AppGuard\Core\Detectors\HoneypotDetector::class,
    AppGuard\Core\Detectors\MaliciousPayloadDetector::class,

    // Daftarkan detektor kustom Anda di sini:
    App\Security\Detectors\MyCustomDetector::class,
],
```

---

### Langkah 4: Uji Coba Mandiri
Buat unit test untuk memverifikasi bahwa:
1. Request normal menghasilkan `null` (tidak ada false positive).
2. Request mencurigakan menghasilkan objek `Signal` dengan skor dan deskripsi yang tepat.
