# 💻 Operasi CLI & Perintah Artisan — AppGuard

Panduan penggunaan perintah Artisan di terminal untuk tim operasional dan administrator sistem.

---

## 1. Memeriksa Status & Skor IP (`guard:status`)

Untuk mengetahui berapa akumulasi skor pelanggaran sebuah alamat IP dan apakah IP tersebut sedang terblokir:

```bash
php artisan guard:status 114.122.10.4
```

### Contoh Output:
```text
IP: 114.122.10.4
Status: BLOCKED
Score: 100
```

Jika IP berstatus wajar:
```text
IP: 180.252.12.8
Status: OK
Score: 0
```

---

## 2. Memblokir IP Secara Manual (`guard:block`)

Jika Anda menemukan aktivitas mencurigakan dari IP tertentu di log server, Anda dapat memblokirnya langsung tanpa perlu menunggu detektor otomatis:

```bash
# Blokir IP selama 60 menit (default)
php artisan guard:block 114.122.10.4

# Blokir IP dengan durasi kustom (misal 120 menit)
php artisan guard:block 114.122.10.4 --minutes=120
```

Selama masa pemblokiran aktif, setiap request dari IP tersebut akan langsung ditolak dengan status HTTP 403 Forbidden.

---

## 3. Membuka Blokir IP (`guard:unblock`)

Jika IP pelanggan/pemohon sah tidak sengaja terblokir (*false positive*) atau masa investigasi telah selesai:

```bash
php artisan guard:unblock 114.122.10.4
```

Perintah ini akan:
1. Menghapus status blokir IP dari cache.
2. Mereset akumulasi skor pelanggaran IP tersebut kembali ke 0.
