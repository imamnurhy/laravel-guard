# 📝 TODO — Laravel Guard (AppGuard Package)

> Backlog dan roadmap pengembangan library keamanan aplikasi terpusat `explorin/laravel-guard`.
> Riwayat task yang telah selesai terdokumentasi di [`CHANGELOG.md`](./CHANGELOG.md).

## 📍 Status Marker

> - `[ ]` Belum dikerjakan
> - `[/]` Sedang dikerjakan
> - `[x]` Selesai (dipindahkan ke `CHANGELOG.md`)

---

## 🔥 Prioritas Pengembangan

### 🚀 Optimasi Internal Sinkronisasi Control Plane (Zero Redis Bloat — Tanpa Ubah config/guard.php)
- [x] **Preservasi Penuh Konfigurasi Eksisting (Zero-Config Change)**:
  - Tidak mengubah skema berkas `config/guard.php` dan tidak menambah variabel `.env` baru.
  - Mempertahankan `guard.store` eksisting murni untuk runtime reputation counter (skor IP/user, rate-limiting, dan buffer insiden telemetri).
- [x] **Internal File-Compiled Snapshot Engine (OPcache Native di Bawah Layar)**:
  - Menyimpan hasil sinkronisasi Control Plane secara otomatis ke berkas compiled PHP lokal (`storage/app/guard/rules_{appKey}.php`) dengan struktur hash map $O(1)$ (`['1.2.3.4' => 1]`).
  - Berjalan otomatis di level internal library tanpa memerlukan konfigurasi manual dari pengguna, memanfaatkan OPcache untuk akses instan (0 ms socket network, 0 byte RAM Redis).
- [x] **Refaktor `SyncCommand.php` — Eliminasi Duplikasi & Telemetry Poisoning**:
  - Menghentikan pemanggilan loop `$guard->block()` per IP dari data snapshot yang membuat ribuan individual keys (`block:ip:*`) di Redis.
  - Mencegah pembuatan objek `BanRecord` massal dan perekaman insiden palsu ke buffer `vulnerabilityStore` untuk IP bawaan snapshot Control Plane.
  - Mengganti pembacaan array besar `Cache::get()` di `Guard::inspect()` dengan lookup hash map internal, menghilangkan transfer data Redis di setiap incoming request.
- [x] **Pengujian & Validasi Backward Compatibility**:
  - Memastikan integrasi berjalan 100% transparan pada aplikasi host tanpa perlu mengubah konfigurasi yang sudah ada.
  - Uji performa inspeksi per request (*latency check*), memory benchmark Redis, dan verifikasi fail-open jika file snapshot belum terbentuk.

### 🛡️ Standarisasi Zero Trust & Safe Defaults (Non-Destructive IP Ban & Collateral Damage Prevention)
- [x] **Default Safe Mode (`ip_ban.enabled = false`)**:
  - Mengubah nilai default `config('guard.ip_ban.enabled')` menjadi `false` (`GUARD_IP_BAN_ENABLED=false`).
  - Mencegah auto-ban IP publik yang dipakai bersama (CGNAT / NAT kantor / ISP dinamis) sehingga rekan sekantor dan warga tidak terkunci secara massal.
  - Memastikan jika blok `ip_ban` dihapus dari berkas `config/guard.php` di host app (seperti `simponie-v3`), sistem tetap berjalan 100% aman (fallback `?? false`).
- [x] **Preservasi Proteksi WAF & Identity-Centric Defense**:
  - Seluruh detektor WAF (Honeypot, SQLi, XSS, Path Traversal, Parameter Tampering, Shannon Entropy) tetap aktif 100% menolak request berbahaya seketika dengan HTTP 403 Forbidden.
  - Penalti difokuskan pada identitas pelaku: User Auto-Banned di database (`c_status = 1`), Force Logout sesi seketika, dan rate-limiting per-akun/pair brute force.
  - Pengecekan snapshot IP blacklist di `Guard::inspect()` diselaraskan agar tunduk pada toggle `ip_ban.enabled`.
- [x] **Preservasi Manual Block & CLI Tooling**:
  - Perintah artisan `guard:block`, `guard:unblock`, dan `guard:status` tetap dipertahankan penuh untuk kebutuhan mitigasi darurat manual oleh admin SOC.
- [x] **Pengujian & Validasi Dokumentasi**:
  - Tambahkan skenario uji smoke test untuk memvalidasi keamanan ketika `ip_ban.enabled = false` atau config `ip_ban` dihilangkan.
  - Dokumentasikan perilaku Zero Trust di panduan dan dokumentasi package.
- [x] **Recursive Config Merging (`GuardServiceProvider`)**:
  - Mengganti shallow `mergeConfigFrom` bawaan Laravel dengan `mergeConfigRecursive` di `GuardServiceProvider`.
  - Memungkinkan aplikasi host (`simponie-v3`) merampingkan `config/guard.php` dari 420 baris menjadi ~100 baris hanya dengan menulis overrides khusus (`safe_fields`, `user_ban.attributes`, `strict.paths`) tanpa kehilangan konfigurasi default detektor bawaan (`honeypot`, `brute_force`, `rules`, dsb).
- [x] **Safe Config Audit & Sync Command (`guard:config`)**:
  - Implementasi perintah `php artisan guard:config` ([ConfigCommand.php](./src/Console/ConfigCommand.php)) untuk mengaudit, membandingkan (`--diff`), menampilkan potongan kode (`--snippet`), dan menyinkronkan (`--sync`) opsi konfigurasi baru ke `config/guard.php` host app.
  - Mekanisme sinkronisasi aman: otomatis membuat berkas cadangan (`.bak_timestamp`), menyisipkan blok kode dengan komentar lengkap sebelum penutup `];`, dan memvalidasi sintaks via linter PHP dengan auto-rollback bila terjadi kesalahan sintaks.
  - Dokumentasi penggunaan di [`01-installation-config.md`](./docs/01-installation-config.md) dan [`05-artisan-cli.md`](./docs/05-artisan-cli.md).

---

## 🎯 Backlog & Eksplorasi Mendatang

- [ ] Evaluasi performa penanganan antrean async tebot/telemetri pada high-throughput traffic.
- [ ] Penambahan driver store persistensi alternatif untuk environment multi-region cluster.

