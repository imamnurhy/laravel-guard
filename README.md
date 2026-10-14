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
