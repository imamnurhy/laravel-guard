# 🛡️ Detektor Bawaan & Sistem Scoring — AppGuard

Panduan mendalam mengenai 7 detector bawaan, algoritma akumulasi reputasi, dan cara membuat custom detector.

---

## 1. Rumus Evaluasi & Scoring

AppGuard tidak menggunakan *if-else* kaku. Setiap request dievaluasi dengan rumus:

$$\text{Total Skor} = \text{Skor Reputasi Tersimpan (IP / User)} + \sum \text{Sinyal Pelanggaran Saat Ini}$$

### Ambang Batas Tindakan (Actions):
1. **Allow (Lolos):** Jika $\text{Skor} < 50$. Request diteruskan normal ke controller.
2. **Throttle (HTTP 429):** Jika $\text{Skor} \ge 50$ dan $< 100$. Klien dibatasi hanya boleh mengirim maksimal 10 request per menit. Disertai header `Retry-After: 60`.
3. **Block (HTTP 403):** Jika $\text{Skor} \ge 100$. Request langsung ditolak di middleware tanpa membebani controller atau database.

---

## 2. Rincian 7 Detektor Bawaan

### 1. `HoneypotDetector` (Fase PRE)
- **Tujuan:** Menjebak scanner otomatis dan bot spam formulir.
- **Mekanisme:**
  - Memeriksa apakah URI path mengarah ke file sensitif yang tidak seharusnya diakses publik (`.env*`, `.git/*`, `wp-admin*`, `phpmyadmin*`, `backup*.sql`).
  - Memeriksa keberadaan field formulir tak terlihat (*hidden honeypot trap field*). Jika diisi oleh bot, langsung ditandai.
- **Skor:** 100 poin (langsung diblokir).

### 2. `BruteForceDetector` (Fase PRE & Event Laravel)
- **Tujuan:** Mencegah serangan tebak sandi akun.
- **Mekanisme:** Terhubung otomatis ke event Laravel `Illuminate\Auth\Events\Failed` dan `Login`.
  - Melacak kegagalan per IP (maks. 20 gagal).
  - Melacak kegagalan per pasangan IP + Akun (maks. 5 gagal).
  - Melacak kegagalan per Akun (maks. 8 gagal $\rightarrow$ skor 60). Diberi skor throttle (bukan langsung block) untuk mencegah penyerang sengaja mengunci akun orang lain (*Denial of Service* akun).
- **Reset:** Login yang berhasil otomatis mereset counter pasangan IP + Akun tersebut.

### 3. `PathTraversalDetector` (Fase PRE)
- **Tujuan:** Menangkal upaya pembacaan file sistem sembarangan (*Local File Inclusion* / Directory Traversal).
- **Mekanisme:** Memindai pola `../`, `..\`, `%2e%2e`, `%00` (null-byte), `/etc/passwd`, dan `C:\windows` baik pada URL maupun parameter query/input.
- **Skor:** 50 poin.

### 4. `MaliciousPayloadDetector` (Fase PRE)
- **Tujuan:** Menangkal serangan injeksi paling umum (SQL Injection & XSS).
- **Mekanisme:**
  - **SQLi:** Mencocokkan konstruksi query serangan nyata (`union select`, `information_schema`, `sleep()`, `' or 1=1--`). Skor: 100 poin.
  - **XSS:** Mencocokkan injeksi script aktif (`<script>`, `onerror=`, `onload=`, `javascript:`). Skor: 50 poin.
  - Mendukung `safe_fields` whitelist untuk mengabaikan field input yang wajar berisi teks bebas (misal `alamat`, `catatan`, `keterangan`).

### 5. `ParameterTamperingDetector` (Fase PRE)
- **Tujuan:** Menangkal eskalasi hak akses / manipulasi status oleh pengguna biasa.
- **Mekanisme:** Memeriksa apakah request mutasi (POST/PUT/PATCH) mengandung parameter sensitif yang dilarang diinjeksikan oleh pengguna (seperti `c_status`, `is_admin`, `role`, `role_id`).
- **Skor:** 35 poin.

### 6. `AnomalyDetector` (Shannon Entropy & URL Fuzzing)
- **Tujuan:** Mendeteksi muatan terenkripsi/obfuscated serta scanner fuzzing.
- **Mekanisme:**
  - **Shannon Entropy (PRE):** Menghitung keacakan string pada input teks panjang ($> 120$ karakter). Nilai di atas $4.5$ mengindikasikan ciphertext/shellcode tersembunyi.
  - **URL Fuzzing (POST):** Melacak lonjakan respon HTTP 404 dari IP yang sama. Jika mengakses minimal 15 URL berbeda dalam rentang 30 detik, IP ditandai sebagai automated fuzzer.
- **Skor:** Entropy (35 poin), Fuzzing (50 poin).

### 7. `DeniedAccessDetector` (Fase POST)
- **Tujuan:** Mendeteksi *forced browsing* dan *enumeration*.
- **Mekanisme:** Memantau akumulasi respon HTTP 403 (dilarang policy) dan 404 (model tidak ditemukan) dalam jendela 60 detik. Mengabaikan aset statis seperti `favicon.ico` dan `robots.txt`.
- **Skor:** 40 poin jika melampaui 15 kali penolakan.

---

## 3. Membuat Custom Detector Sendiri

Anda dapat menambahkan detector buatan sendiri dengan mengimplementasikan interface `AppGuard\Core\Contracts\Detector`:

```php
namespace App\Security\Detectors;

use AppGuard\Core\Contracts\Detector;
use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

class ApiKeyHeaderDetector implements Detector
{
    public function name(): string
    {
        return 'api_key_check';
    }

    public function inspect(RequestContext $ctx): array
    {
        // Contoh: Cek header khusus pada rute /api/*
        if (str_starts_with($ctx->path, '/api/')) {
            // Lakukan pengecekan kustom...
        }

        return [];
    }

    public function observe(RequestContext $ctx, int $status): array
    {
        return [];
    }
}
```

Daftarkan class tersebut di `config/guard.php`:

```php
'custom_detectors' => [
    App\Security\Detectors\ApiKeyHeaderDetector::class,
],
```
