# 🛡️ Standar Ketersediaan Tinggi & Prinsip Failsafe (Fail-Open)

> Aturan ketat ketahanan sistem, penanganan kegagalan dependensi eksternal, dan efisiensi memori pada package `explorin/laravel-guard`.

---

## ⚡ 1. Prinsip Mutlak: "Security Must Never Break Business"

Sistem keamanan bertindak sebagai penjaga (*guard*), bukan penghambat operasional:

1. **Fail-Open Policy pada Kegagalan Eksternal**:
   - Jika server Redis / Memcached mengalami gangguan (*connection timeout / network partition*), Guard **TIDAK BOLEH** melempar fatal exception HTTP 500 ke pengguna.
   - Guard wajib menangkap exception (`try...catch \Throwable`), mencatat error ke emergency logger, dan **meloloskan request pengguna (fail-open)**.
2. **Isolasi Kegagalan Notifikasi (Tebot / Telegram)**:
   - Jika Telegram API mengalami throttling, down, atau webhook gagal terkirim, `TebotNotifier` wajib menangkap exception dan mengalihkan log ke file `storage/logs/laravel.log`.
   - Kegagalan notifikasi **tidak boleh membatalkan aksi pemblokiran atau mutasi database user**.
3. **Perekaman JSONL Non-Blocking**:
   - Operasi penulisan log celah ke `vulnerabilities.jsonl` menggunakan mode append (`FILE_APPEND | LOCK_EX`) di dalam fase POST `terminate()`, sehingga tidak menambah waktu latensi respon HTTP ke pengguna.

---

## 🏎️ 2. Pencegahan Bottleneck Basis Data pada Perimeter

1. **Jangan Menyentuh Database pada Fase PRE**:
   - Fase PRE **hanya boleh memeriksa cache reputasi (Redis/Memory)** untuk menghitung skor penalti IP/Klien.
   - Pengecekan database hanya diizinkan untuk verifikasi status akun ter-banned jika pengguna sedang terautentikasi (`$request->user()`), dan hasil pemeriksaan wajib dicache (*cached check*).
2. **Penghindaran Query N+1**:
   - Seluruh mutasi ban akun pengguna dilakukan via single query update (`c_status = 1`) pada saat skor mencapai threshold (100).
