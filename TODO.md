# 📝 TODO — Laravel Guard (AppGuard Package)

> Backlog dan roadmap pengembangan library keamanan aplikasi terpusat `explorin/laravel-guard`.
> Riwayat task yang telah selesai terdokumentasi di [`CHANGELOG.md`](./CHANGELOG.md).

## 📍 Status Marker

> - `[ ]` Belum dikerjakan
> - `[/]` Sedang dikerjakan
> - `[x]` Selesai (dipindahkan ke `CHANGELOG.md`)

---

## 🔥 Prioritas Pengembangan

> Seluruh item dari rilis sebelumnya (`[2026-10-19]`) dan rilis (`[2026-10-23]`) telah selesai diuji dan dipindahkan ke [`CHANGELOG.md`](./CHANGELOG.md).

### 1. Multi-Driver Telemetry & Incident Store (`jsonl`, `redis`, `cache`)
Menyediakan dan menyesuaikan sistem penyimpanan buffer telemetri / insiden keamanan agar mendukung berbagai driver penyimpanan (`jsonl`, `redis`, `cache`) yang dapat dipilih cukup melalui satu konfigurasi driver tunggal (`GUARD_STORE` / `GUARD_TELEMETRY_DRIVER`):
- [x] **Konfigurasi Satu Env Driver (`config/guard.php` & `GuardServiceProvider.php`)**:
  - Menyederhanakan penentuan driver penyimpanan telemetri melalui satu variabel environment utama (misal `GUARD_TELEMETRY_DRIVER` atau mengikuti `GUARD_STORE` dengan pilihan: `jsonl`, `redis`, `cache`, `array`, `null`), dengan tetap menjaga kompatibilitas mundur.
  - Menambahkan opsi konfigurasi pendukung untuk antrean telemetri seperti `key` / prefix buffer, `max_items` (batas kapasitas antrean di Redis/Cache agar memori tetap terjaga), serta `ttl` (masa retensi di cache).
- [x] **Penyesuaian Kontrak Store Telemetri / Insiden (`src/Core/Contracts/VulnerabilityStore.php`)**:
  - Menambahkan method manajemen antrean buffer untuk kebutuhan pengiriman telemetri lintas driver, seperti `pullBatch(int $limit = 100): array` (atau `peekBatch` + `acknowledgeBatch` / `flush`) dan `count(): int` agar tidak bergantung pada operasi baca/tulis file fisik `.jsonl` semata.
- [x] **Implementasi Driver Penyimpanan (`redis`, `cache`, `jsonl`)**:
  - [x] Driver `redis`: Menyimpan dan mengambil rekaman telemetri JSON secara atomik menggunakan struktur data Redis (`RPUSH`, `LRANGE`, `LTRIM`) dengan pembatasan kapasitas maksimal (`max_items`).
  - [x] Driver `cache`: Menyimpan buffer telemetri menggunakan `Illuminate\Contracts\Cache\Repository` (mengikuti store cache aktif) dengan mekanisme ring-buffer / array terbatasi dan TTL.
  - [x] Driver `jsonl`, `array`, & `null`: Menyesuaikan implementasi method kontrak baru (`pullBatch` / penghapusan batch setelah dikirim dan `count`) pada store eksisting agar seluruh driver memiliki perilaku yang seragam.
- [x] **Penyesuaian Command CLI (`ShipTelemetryCommand` & `DoctorCommand`)**:
  - [x] Refactor `guard:ship-telemetry` ([ShipTelemetryCommand.php](./src/Console/ShipTelemetryCommand.php)) agar mengambil dan menghapus batch rekaman langsung melalui abstraksi store aktif (mendukung penuh pengiriman dari driver `redis`, `cache`, maupun `jsonl` ke Control Plane).
  - [x] Perbarui `guard:doctor` ([DoctorCommand.php](./src/Console/DoctorCommand.php)) agar pemeriksaan kesehatan *Telemetry / Incident Store* menyesuaikan dengan driver aktif (`redis`, `cache`, atau `jsonl`), tidak lagi hanya mengecek izin tulis direktori `.jsonl`.
- [x] **Pengujian & Dokumentasi**:
  - [x] Menambahkan unit/smoke test di `tests/smoke.php` untuk menguji perekaman telemetri, pembatasan kapasitas buffer, dan proses *ship telemetry* pada driver `jsonl`, `redis`, dan `cache`.
  - [x] Memperbarui dokumentasi konfigurasi driver telemetri pada `README.md` dan `docs/`.

### 2. Standardisasi Tampilan Tabel Terminal pada Seluruh Command CLI
Menyeragamkan format output terminal agar seluruh command inspeksi status dan daftar ban menggunakan komponen tabel bergaya box-drawing (`TableStyle`) yang konsisten dan mudah dibaca:
- [x] **Penyesuaian `guard:status {ip?}` ([StatusCommand.php](./src/Console/StatusCommand.php))**:
  - Mengubah output status global sistem (`enabled`, `mode`, `fail_open`, `store`, jumlah ban aktif, driver telemetri) dan status spesifik IP (`mode`, `blocked`, `reputasi`, `threshold`, detail `BanRecord` bila ada) menjadi tampilan tabel terstruktur dengan badge warna seperti pada `guard:ban` dan `guard:doctor`.
  - Menambahkan opsi `--json` untuk kebutuhan otomasi/healthcheck script.
- [x] **Penyesuaian `guard:user-status {userId}` ([UserStatusCommand.php](./src/Console/UserStatusCommand.php))**:
  - Mengubah tampilan inspeksi status blokir user, skor penalti, metadata pemblokiran terakhir (`alasan`, `waktu`, `ip pelaku`, `sisa TTL`), serta status kolom model database menjadi format tabel `['Atribut', 'Nilai']` yang rapi dan seragam dengan `guard:ban show`.
  - Menambahkan opsi `--json`.
- [x] **Penyempurnaan Tabel Daftar Ban pada `guard:ban list` ([BanCommand.php](./src/Console/BanCommand.php))**:
  - Tetap merender struktur header tabel (atau baris *empty state* di dalam tabel) saat daftar ban kosong agar tata letak visual di terminal selalu konsisten.

### 3. Fitur Clear / Flush Seluruh Ban Sekaligus (`guard:ban clear`)
Menambahkan kemampuan untuk membuka/membersihkan seluruh daftar ban aktif (IP & User) secara massal melalui API Core maupun Artisan CLI:
- [x] **Penambahan Method Clear pada `BanRegistry` & `Guard` ([BanRegistry.php](./src/Core/Contracts/BanRegistry.php), [CacheBanRegistry.php](./src/Stores/CacheBanRegistry.php), [ArrayBanRegistry.php](./src/Core/Stores/ArrayBanRegistry.php), [Guard.php](./src/Core/Guard.php))**:
  - Menambahkan kontrak `clear(?string $type = null): int` pada `BanRegistry` dan method `Guard::clearBans(?string $type = null, string $liftedBy = 'cli', string $reason = 'Bulk clear'): int` yang mengiterasi seluruh ban aktif, memanggil `unblock()` / `unbanUser()` (agar key store, skor reputasi, force logout, dan event `BanLifted` ikut dibersihkan dengan benar), serta mengosongkan indeks ban.
- [x] **Sub-Aksi CLI `php artisan guard:ban clear` / `flush` & Opsi `--all` ([BanCommand.php](./src/Console/BanCommand.php))**:
  - Menambahkan aksi `guard:ban clear` (alias `flush` atau `guard:ban unban --all`) dengan dukungan filter `--type=ip|user`, `--sync-db` (memulihkan status akun user di database), `--force` (tanpa konfirmasi interaktif), dan `--json`.
  - Menampilkan konfirmasi jumlah ban yang akan dibersihkan beserta tabel ringkasan hasil eksekusi di terminal.
- [x] **Pengujian & Dokumentasi**:
  - Menambahkan test case `clearBans` dan `guard:ban clear` pada [smoke.php](./tests/smoke.php) serta memperbarui dokumentasi CLI di `README.md` dan `docs/05-artisan-cli.md`.

---

### Backlog & Eksplorasi Mendatang
- [ ] Evaluasi performa penanganan antrean async tebot/telemetri pada high-throughput traffic.
- [ ] Penambahan driver store persistensi alternatif untuk environment multi-region cluster.
