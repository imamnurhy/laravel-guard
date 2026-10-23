# 💻 Operasi CLI & Perintah Artisan — AppGuard

Panduan komprehensif seluruh perintah Artisan di terminal untuk tim operasional, developer, dan administrator sistem.

---

## 1. Perintah Terpadu Manajemen Ban (`guard:ban`)

Perintah terpadu untuk monitoring, audit, dan pembukaan blokir IP maupun akun pengguna dengan antarmuka tabel interaktif:

```bash
# Melihat daftar seluruh IP & User yang diblokir saat ini
php artisan guard:ban
# atau
php artisan guard:ban list

# Opsi filter daftar:
php artisan guard:ban list --type=ip                    # Hanya tampilkan IP
php artisan guard:ban list --type=user                  # Hanya tampilkan user
php artisan guard:ban list --search="sql"               # Cari berdasarkan keyword
php artisan guard:ban list --sort=expiring              # Urutkan berdasarkan waktu berakhir terdekat
php artisan guard:ban list --limit=20 --json            # Output format JSON

# Melihat rincian lengkap suatu subject (termasuk status kolom database user):
php artisan guard:ban show 192.168.1.10
php artisan guard:ban show 42 --type=user

# Cek cepat status blokir (exit code 1 jika diblokir, 0 jika aman):
php artisan guard:ban check 192.168.1.10

# Melihat statistik dan visualisasi proporsi detektor:
php artisan guard:ban stats

# Membuka blokir (interaktif memilih daftar jika subject dikosongkan):
php artisan guard:ban unban 192.168.1.10
php artisan guard:ban unban 42 --type=user --sync-db

# Membersihkan seluruh daftar ban aktif sekaligus (IP & User, atau filter --type):
php artisan guard:ban clear --force
php artisan guard:ban clear --type=ip --force
php artisan guard:ban clear --type=user --sync-db --force

# Rekonsiliasi sinkronisasi ban antara Redis lokal dan Control Plane:
php artisan guard:ban sync
```

---

## 2. Diagnostik Sistem & Health Check (`guard:doctor`)

Mengecek kesiapan konfigurasi, koneksi ke Redis/Cache store, izin tulis folder dataset log forensik, dan konektivitas Control Plane:

```bash
php artisan guard:doctor
php artisan guard:doctor --json
```

---

## 3. Uji Coba Rule & Payload Dry-Run (`guard:test-rule`)

Menguji apakah suatu request atau muatan payload berbahaya akan terdeteksi oleh modul WAF tanpa mengubah atau menyimpan skor ke cache Redis:

```bash
# Uji path honeypot
php artisan guard:test-rule /.env

# Uji input injection SQLi
php artisan guard:test-rule /search --input="q=' union select 1,2,3--"

# Uji profil tertentu dengan HTTP method POST
php artisan guard:test-rule /api/checkout --method=POST --profile=strict --input="is_admin=1"
```

---

## 4. Status Sistem & Operasi IP Klasik (`guard:status`, `guard:block`, `guard:unblock`)

### A. Cek Status IP / Sistem (`guard:status`)
```bash
# Cek status global sistem
php artisan guard:status

# Cek status spesifik alamat IP
php artisan guard:status 114.122.10.4
```

### B. Blokir IP Manual (`guard:block`)
```bash
php artisan guard:block 114.122.10.4 --minutes=120 --reason="Aktivitas mencurigakan"
```

### C. Buka Blokir IP (`guard:unblock`)
```bash
php artisan guard:unblock 114.122.10.4
```

---

## 5. Operasi Manajemen User (`guard:user-status`, `guard:ban-user`, `guard:unban-user`)

```bash
# Melihat skor reputasi dan status pemblokiran user di cache & database
php artisan guard:user-status 105

# Memblokir akun user secara manual
php artisan guard:ban-user 105 --reason="Pelanggaran ketentuan layanan"

# Membuka blokir user dan menyinkronkan status di database kembali aktif
php artisan guard:unban-user 105 --sync-db
```

---

## 6. Integrasi & Sinkronisasi Control Plane (`guard:sync`, `guard:ship-telemetry`, `guard:heartbeat`)

```bash
# Sinkronisasi remote policy, dynamic honeypot, dan antrean perintah
php artisan guard:sync
php artisan guard:sync --force

# Pengiriman rekaman telemetri buffer (jsonl, redis, atau cache) ke server pusat
php artisan guard:ship-telemetry --batch-size=100

# Pengiriman status heartbeat kesehatan sensor
php artisan guard:heartbeat
```
