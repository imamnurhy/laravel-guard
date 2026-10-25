# ⚙️ Instalasi & Konfigurasi — AppGuard

Panduan lengkap instalasi, opsi environment `.env`, dan konfigurasi `config/guard.php`.

---

## 1. Instalasi

Jalankan perintah Composer pada proyek Laravel:

```bash
composer require explorin/laravel-guard
```

Publish file konfigurasi `guard.php` ke direktori `config/`:

```bash
php artisan vendor:publish --tag=guard-config
```

---

## 2. Pengaturan Environment (`.env`)

Tambahkan variabel berikut ke file `.env` aplikasi Anda:

```env
# Mode kerja:
# - 'monitor' : Hanya mencatat insiden ke log (aman untuk uji coba awal/profiling)
# - 'enforce' : Aktif menolak request mencurigakan (403/429) & auto-banned
GUARD_MODE=enforce

# Cache store: Disarankan 'redis' pada server produksi untuk performa cepat & multi-worker
GUARD_CACHE_STORE=redis

# Driver penyimpanan buffer telemetri insiden: 'jsonl' (default), 'redis', 'cache', 'array', atau 'null'
GUARD_TELEMETRY_DRIVER=jsonl
GUARD_TELEMETRY_MAX_ITEMS=5000

# Ambang batas reputasi IP
GUARD_THROTTLE_THRESHOLD=50
GUARD_BLOCK_THRESHOLD=100
GUARD_REPUTATION_TTL=1800

# Fitur Auto-Banned Pengguna
GUARD_USER_BAN_ENABLED=true
GUARD_USER_BAN_THRESHOLD=100
GUARD_USER_MODEL="App\Models\User"

# Integrasi Notifikasi Telegram (Tebot)
GUARD_TEBOT_ENABLED=true

# Channel Log khusus (opsional, default memakai log utama Laravel)
GUARD_LOG_CHANNEL=null
```

---

## 3. Penjelasan Lengkap File `config/guard.php`

| Opsi | Default | Penjelasan |
|---|---|---|
| `enabled` | `true` | Saklar utama untuk mengaktifkan atau menonaktifkan AppGuard secara global. |
| `mode` | `'monitor'` | Menentukan apakah penolakan request benar-benar dieksekusi (`enforce`) atau hanya dicatat (`monitor`). |
| `fail_open` | `true` | Jika backend cache (misal Redis) mati, `true` akan meloloskan request agar aplikasi tidak lumpuh (resilient). |
| `store` | `null` | Menentukan driver cache Laravel yang digunakan untuk menyimpan counter skor dan status blokir. |
| `auto_register` | `true` | Otomatis mendaftarkan `GuardMiddleware` ke Kernel HTTP global (setelah middleware `TrustProxies`). |
| `allowlist` | `[]` | Daftar IP address yang tidak akan pernah diinspeksi (misal IP server monitoring / payment gateway). |
| `thresholds` | `['throttle' => 50, 'block' => 100]` | Ambang batas poin penalti sebelum request terkena pembatasan laju atau penolakan total. |
| `profiles` | `['strict' => [...]]` | Penyesuaian ambang batas khusus untuk rute sensitif tertentu (seperti `/login`, `/register`). |
| `ip_ban` | `['enabled' => false, 'duration' => 1800]` | Pemblokiran IP otomatis (default: `false` demi Zero Trust & ramah NAT kantor/CGNAT). Detektor WAF tetap menolak HTTP 403 per request. |
| `user_ban` | `[...]` | Konfigurasi pemblokiran akun di basis data, kolom status, durasi, dan rute pengalihan logout. |
| `tebot` | `['enabled' => true]` | Saklar pengiriman alert Telegram via package `explorin/tebot`. |
| `vulnerability` | `[...]` | Lokasi penyimpanan dataset insiden JSONL untuk keperluan audit & Machine Learning. |
| `rules` | `[...]` | Bobot poin penalti per kategori pelanggaran logika bisnis (IDOR, Tampering, SQLi, dsb). |
| `detectors` | `[...]` | Konfigurasi parameter masing-masing detektor bawaan. |
| `custom_detectors` | `[]` | Array class detector kustom buatan developer sendiri. |

---

## 4. Konfigurasi TrustProxies (PENTING!)

Karena AppGuard menilai reputasi berdasarkan alamat IP pengirim, **pastikan konfigurasi `TrustProxies` aplikasi Laravel Anda sudah benar**:
- Jika di belakang Cloudflare, Nginx, Traefik, atau Docker Swarm, pastikan header `X-Forwarded-For` atau `CF-Connecting-IP` dipercaya oleh Laravel agar IP yang dinilai adalah IP asli pengunjung, bukan IP proxy lokal.

---

## 5. Pola Konfigurasi Minimalis (Delta Overrides) & Sinkronisasi Aman

AppGuard mendukung **Recursive Config Merging**, yang memungkinkan aplikasi host (seperti `simponie-v3`) hanya menuliskan opsi kustom yang ingin diubah pada `config/guard.php` tanpa perlu menduplikasi seluruh 400+ baris konfigurasi default package.

### A. Konsep Delta Overrides
- Setiap opsi yang tidak ditulis di `config/guard.php` host akan **otomatis diwarisi** dari default package saat runtime.
- Ketika ada fitur atau opsi baru dari pembaruan package, opsi tersebut **langsung aktif di memori** tanpa mengharuskan perubahan pada berkas `config/guard.php` host.

### B. Manajemen & Sinkronisasi Konfigurasi (`guard:config`)
Gunakan perintah CLI bawaan untuk memeriksa dan menyinkronkan konfigurasi secara aman:

```bash
# 1. Audit status konfigurasi (Kustom vs Diwarisi):
php artisan guard:config

# 2. Perbandingan detail (diff):
php artisan guard:config --diff

# 3. Lihat snippet kode siap salin untuk opsi tertentu:
php artisan guard:config --snippet=ip_ban

# 4. Sinkronkan opsi baru/absen ke dalam config/guard.php host secara aman (otomatis backup):
php artisan guard:config --sync --key=<nama_opsi>
```
