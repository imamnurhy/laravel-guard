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
