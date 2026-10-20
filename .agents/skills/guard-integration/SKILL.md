---
name: guard-integration
description: Panduan komprehensif integrasi package explorin/laravel-guard ke berbagai aplikasi host Laravel (WAF perimeter, mitigasi IDOR di controller, auto-banned user database c_status, notifikasi Tebot Telegram, dan analisis dataset vulnerabilities.jsonl).
---

# 🛡️ AppGuard Integration Skill (Laravel Host Application)

Skill ini memandu AI Assistant dan Pengembang dalam mengintegrasikan dan mengonfigurasikan package `explorin/laravel-guard` ke dalam aplikasi web Laravel apa pun secara adaptif dan teruji.

---

## 📋 Prosedur Langkah demi Langkah

### Langkah 1: Instalasi & Publikasi Konfigurasi
Jalankan di root aplikasi host Laravel:
```bash
composer require explorin/laravel-guard
php artisan vendor:publish --tag=guard-config
```
File konfigurasi akan tersedia di `config/guard.php`.

---

### Langkah 2: Konfigurasi Environment (`.env`)
Sesuaikan variabel environment pada aplikasi host:
```dotenv
# Mode: 'enforce' (blokir aktif) atau 'monitor' (catat log tanpa memblokir)
GUARD_MODE=enforce

# Cache store untuk reputasi IP (disarankan 'redis' di production)
GUARD_CACHE_STORE=redis

# Fitur Auto-Banned Pengguna
GUARD_USER_BAN_ENABLED=true
GUARD_USER_MODEL=App\Models\User
GUARD_USER_STATUS_COLUMN=c_status
GUARD_USER_BANNED_VALUE=1

# Ambang batas skor pelanggaran (Default: 100)
GUARD_SCORE_BLOCK=100
GUARD_SCORE_THROTTLE=50

# Notifikasi Darurat Telegram (Tebot)
GUARD_TEBOT_ENABLED=true
GUARD_TEBOT_CHAT_ID=-1001234567890
```

---

### Langkah 3: Proteksi Logika Bisnis & Mitigasi IDOR di Controller
Gunakan facade `AppGuard\Facades\SecurityGuard` pada controller untuk mencatat pelanggaran akses data tidak sah:

```php
use AppGuard\Facades\SecurityGuard;

public function downloadDokumen($id)
{
    $dokumen = Dokumen::findOrFail($id);

    // Verifikasi Hak Kepemilikan (Anti-IDOR)
    if ($dokumen->user_id !== auth()->id()) {
        // Catat penalti 25 poin
        SecurityGuard::recordViolation(
            user: auth()->user(),
            type: 'idor_attempt',
            score: 25,
            reason: "Mencoba mengunduh dokumen ID {$id} milik pengguna lain"
        );

        abort(403, 'Anda tidak memiliki hak akses ke dokumen ini.');
    }

    return response()->download($dokumen->file_path);
}
```
> **Catatan Alur Otomatis**: Jika akumulasi poin pelanggaran user mencapai `GUARD_SCORE_BLOCK` (100), AppGuard otomatis memutasi kolom status database user (`c_status = 1`), membersihkan sesi login (*force logout*), memicu event `AppGuard\Events\UserBanned`, dan mengirim alert via Telegram.

---

### Langkah 4: Kustomisasi User Ban Handler (Jika Skema Database Berbeda)
Jika aplikasi host memiliki skema kolom status yang berbeda (misal `is_active = false`, `status = 'suspended'`), implementasikan handler kustom:

1. Buat class handler kustom mengimplementasikan `AppGuard\Contracts\UserBanHandler`.
2. Daftarkan di `config/guard.php`:
   ```php
   'user_ban' => [
       'handler' => App\Security\CustomBanHandler::class,
   ],
   ```

*(Lihat [EXAMPLE.md](./EXAMPLE.md) untuk template kustom ban handler).*

---

### Langkah 5: Inspeksi & Audit Data Forensik
Periksa status keamanan dan celah yang tercatat menggunakan perintah Artisan:
```bash
# Periksa status reputasi IP
php artisan guard:status 192.168.1.100

# Blokir atau buka blokir IP secara manual
php artisan guard:block 192.168.1.100 --reason="Manual investigation"
php artisan guard:unblock 192.168.1.100

# Inspeksi berkas dataset celah keamanan
tail -f storage/logs/vulnerabilities.jsonl
```
