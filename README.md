# AppGuard for Laravel & PHP (`explorin/laravel-guard`)

> **Application-Level Security Guard, Scoring-Based WAF, and Autonomous Anti-Banned with Vulnerability Dataset Capture.**

`app-guard` adalah package keamanan modular yang menggabungkan kemampuan **Network/Perimeter WAF** (deteksi bot, brute force, honeypot, scanning/fuzzing) dengan **Domain & Business Logic Guard** (IDOR, tampering, auto-banned user, dan penutupan celah).

Dibangun dengan prinsip **Scoring-based Detection** (bukan if-else kaku), berjalan sebelum request mencapai controller (PRE) dan belajar dari respon controller (POST), serta dilengkapi **Vulnerability Store (JSONL)** untuk mencatat celah yang terekspose sebagai dataset pelatihan Machine Learning masa depan.

---

## ⚡ 3-Step Quick Start

### 1. Instalasi
```bash
composer require explorin/laravel-guard
php artisan vendor:publish --tag=guard-config
```

### 2. Konfigurasi `.env`
```env
GUARD_MODE=enforce
GUARD_CACHE_STORE=redis
GUARD_USER_BAN_ENABLED=true
GUARD_USER_MODEL=App\Models\User
GUARD_TEBOT_ENABLED=true
```

### 3. Gunakan di Controller (Pencegahan IDOR)
```php
use AppGuard\Facades\SecurityGuard;

if ($permohonan->user_id !== auth()->id()) {
    SecurityGuard::recordViolation(auth()->user(), 'idor', 25, "Percobaan akses dokumen orang lain");
    abort(403);
}
```
*(Jika pelanggaran mencapai 100 poin, akun otomatis di-banned `c_status = 1`, dipaksa logout, dan notifikasi Telegram terkirim).*

---

## 🎛️ Cookbook Penggunaan Fleksibel

### 1. Parameter Middleware Per-Route / Group & `#[GuardProfile]`
```php
use AppGuard\Attributes\GuardProfile;

// Pilih profile preset, batasi detektor, atau ubah ambang skor langsung di route:
Route::middleware('guard:strict')->group(...);
Route::post('/webhook/payment', ...)->middleware('guard:bypass');
Route::post('/search', ...)->middleware('guard:waf,threshold=60,mode=monitor');

// Atau gunakan PHP Attribute pada Controller / Method:
#[GuardProfile('strict', block: 60)]
class CheckoutController extends Controller
{
    #[GuardProfile(mode: 'monitor', detectors: ['honeypot', 'malicious_payload'])]
    public function preview() { ... }
}
```

### 2. Monitoring & Operasional CLI via Artisan

AppGuard menyediakan serangkaian perintah CLI lengkap untuk monitoring, pengujian, sinkronisasi, dan manajemen keamanan:

```bash
# === Manajemen Ban Terpadu (IP & User) ===
php artisan guard:ban                       # Tabel daftar IP & user yang sedang diban
php artisan guard:ban list --type=ip        # Filter daftar berdasarkan tipe (ip / user)
php artisan guard:ban show 203.0.113.50     # Detail mendalam status & reputasi IP / user
php artisan guard:ban check 203.0.113.50    # Cek cepat (exit code non-zero jika terblokir - cocok untuk CI/Script)
php artisan guard:ban stats                 # Statistik agregat ban aktif & grafik mini proporsi detektor
php artisan guard:ban unban 203.0.113.50    # Buka blokir (interaktif jika subject dikosongkan)
php artisan guard:ban sync                  # Rekonsiliasi indeks ban lokal Redis ↔ Control Plane

# === Diagnostik & Dry-Run Pengujian ===
php artisan guard:doctor                    # Health check konfigurasi, koneksi cache/Redis, dataset, & Control Plane
php artisan guard:test-rule /search --input="q=' union select 1--" # Uji coba payload terhadap detektor (tanpa simpan ke Redis)

# === Manajemen Status & Pemblokiran IP ===
php artisan guard:status {ip?}              # Cek status global sistem atau status spesifik IP
php artisan guard:block {ip} --minutes=60   # Blokir IP manual secara instan
php artisan guard:unblock {ip}              # Hapus blokir IP manual & reset reputasi

# === Manajemen Pemblokiran User (Akun) ===
php artisan guard:user-status {userId}      # Cek status ban, skor reputasi, & kolom status database user
php artisan guard:ban-user {userId} --reason="Aktivitas mencurigakan" # Blokir akun user di cache & database
php artisan guard:unban-user {userId} --sync-db # Buka blokir user di cache & pulihkan status di database

# === Sinkronisasi & Integrasi Control Plane ===
php artisan guard:sync                      # Tarik aturan dinamis, honeypots baru, & remote policy
php artisan guard:ship-telemetry            # Kirim batch rekaman insiden (vulnerabilities.jsonl) ke Control Plane
php artisan guard:heartbeat                 # Kirim sinyal heartbeat status kesehatan sensor ke Control Plane
```

### 3. Event Hook, Custom Responder, & Resolver
```php
use AppGuard\Facades\SecurityGuard;

SecurityGuard::onBan(fn ($ban) => logger()->warning("Banned {$ban->id()}"));
SecurityGuard::onBanLifted(fn ($type, $subject, $by) => logger()->info("Unbanned {$type}:{$subject} by {$by}"));
SecurityGuard::respondUsing(fn ($request, $decision) => response()->json(['blocked' => true], 403));
SecurityGuard::resolveTenantUsing(fn ($request) => $request->header('X-Tenant-Id'));
```

---

## 📚 Indeks Dokumentasi Lengkap

Untuk panduan mendalam dan spesifikasi teknis, silakan merujuk pada dokumen berikut:

| Dokumen | Deskripsi |
|---|---|
| 🏛️ **[`ARCHITECTURE.md`](./ARCHITECTURE.md)** | Desain arsitektur internal, POPO Core vs Laravel Adapter, dan siklus hidup request (PRE & POST). |
| 📋 **[`docs/06-incident-dataset.md`](./docs/06-incident-dataset.md)** | Pencatatan insiden/celah (`vulnerabilities.jsonl`), inspeksi forensik, dan roadmap analisis data. |
| ⚙️ **[`docs/01-installation-config.md`](./docs/01-installation-config.md)** | Panduan instalasi detail, opsi environment `.env`, dan penjelasan file konfigurasi. |
| 🛡️ **[`docs/02-detectors-scoring.md`](./docs/02-detectors-scoring.md)** | Penjelasan 7 detektor bawaan, formula scoring, dan tutorial membuat *custom detector*. |
| 👤 **[`docs/03-business-guard-auto-banned.md`](./docs/03-business-guard-auto-banned.md)** | Mitigasi IDOR di controller, mutasi status database, event `UserBanned`, dan *force logout*. |
| 📢 **[`docs/04-tebot-alerts.md`](./docs/04-tebot-alerts.md)** | Integrasi notifikasi darurat Telegram via package Tebot dengan *failsafe logger*. |
| 💻 **[`docs/05-artisan-cli.md`](./docs/05-artisan-cli.md)** | Panduan perintah Artisan (`guard:status`, `guard:block`, `guard:unblock`). |

---

## 🧪 Uji Coba Mandiri (Smoke Test)

Package ini menyediakan script smoke test mandiri yang dapat dijalankan tanpa dependensi database/framework:

```bash
php tests/smoke.php
```
*(Seluruh 19/19 checks pengujian lolos 100%).*

---

## 📄 Lisensi

Open-source di bawah lisensi [MIT](LICENSE).
