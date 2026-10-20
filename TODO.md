# 📝 TODO — Laravel Guard (AppGuard Package)

> Backlog dan roadmap pengembangan library keamanan aplikasi terpusat `explorin/laravel-guard`.
> Riwayat task yang telah selesai terdokumentasi di [`CHANGELOG.md`](./CHANGELOG.md).

## 📍 Status Marker

> - `[ ]` Belum dikerjakan
> - `[/]` Sedang dikerjakan
> - `[x]` Selesai (dipindahkan ke `CHANGELOG.md`)

---

## 🔥 Prioritas Pengembangan

> Rilis sebelumnya (`[2026-10-19]`) telah selesai dan dipindahkan ke [`CHANGELOG.md`](./CHANGELOG.md).

### 1. Fleksibilitas Konfigurasi & Penggunaan (Flexibility)
- [x] **Konfigurasi Per-Route / Per-Group**:
  - [x] Parameter middleware (`guard:waf,threshold=50`, `guard:strict`, `guard:bypass`) agar tiap route/group dapat memilih detektor, mode, & ambang skor sendiri.
  - [x] Atribut/PHP Attribute `#[GuardProfile('strict')]` pada controller/method.
- [x] **Profile Preset (`strict`, `balanced`, `monitor`)**:
  - [x] Preset siap pakai di `config/guard.php` yang bisa di-override sebagian (deep merge).
  - [x] Mode `monitor-only` (log tanpa blokir) per detektor (`detectors.{name}.monitor_only`), bukan hanya global.
- [x] **Detektor Pluggable (Custom Detector API)**:
  - [x] `Detector` contract + `Guard::addDetector()` & registrasi via `config('guard.custom_detectors')`.
  - [x] Bobot skor & aturan WAF dapat diubah lewat config tanpa mengubah kode.
- [x] **Whitelist & Exclusion Fleksibel**:
  - [x] Pengecualian berdasarkan IP/CIDR, path (wildcard), nama field, header, dan user/role (`config('guard.exclusions')`).
  - [x] Closure resolver untuk identitas (`resolveUserUsing`, `resolveTenantUsing`).
- [x] **Driver Storage & Shipper Pluggable**:
  - [x] Driver penyimpanan reputasi & indeks ban (`redis`/`cache`/`array`) serta opsi `key_prefix` & `prefix_by_tenant` via config.
  - [x] Driver penyimpanan telemetri/insiden (`jsonl`, `array`, `null`) via `config('guard.vulnerability.driver')`.
- [x] **Event & Hook Extensibility**:
  - [x] Event `RequestScored`, `IncidentRecorded`, `IpBlocked`, `BanLifted`, `UserBanned` serta callback `onBan()`, `onBanLifted()`, `onIncident()`, `onScored()`.
  - [x] Respons blokir kustom (`respondUsing`) untuk web/JSON/API.

### 2. Ban Management & Unban (Dukungan Control Plane)
> Ban/blokir disimpan di **Redis** tenant (key ber-TTL), sehingga perlu indeks & sinkronisasi agar dapat didaftar dan di-unban dari Control Plane.
- [x] **Indeks Ban di Redis (`BanRegistry`)**:
  - [x] Selain key ban ber-TTL, simpan indeks (`CacheBanRegistry` di key `guard:bans:index` dengan metadata `BanRecord`: tipe, subject, alasan, sumber/detektor, skor, `banned_at`, `expires_at`, IP) agar listing tanpa `KEYS`/`SCAN` mahal.
  - [x] Pembersihan indeks otomatis untuk ban kedaluwarsa dan rekonsiliasi saat key TTL habis.
  - [x] Prefix key per tenant (`key_prefix` & `prefix_by_tenant`) & konfigurasi store khusus.
- [x] **Payload Event Ban Lengkap**:
  - [x] Event `IpBlocked`/`UserBanned` membawa subject (IP/user ID/email), tipe, detektor pemicu, skor, alasan, `banned_at`, `expires_at`, dan tenant.
  - [x] Shipper mengirim event ban ke Control Plane (`ban.created`, `ban.lifted`) sehingga Control Plane memiliki salinan (snapshot) untuk UI.
  - [x] Command `guard:ban sync` untuk rekonsiliasi penuh Redis → Control Plane (backfill/koreksi drift).
- [x] **Unban API**:
  - [x] Method `Guard::bans()`, `Guard::findBan()`, `Guard::unblock()`, dan `Guard::unbanUser()` terintegrasi dengan `BanRegistry`.
  - [x] Unban dari Control Plane diterapkan ke Redis tenant: via webhook (`unban_ip`, `unban_user`) maupun pull queue (`guard:sync` + `/commands/ack` & `guard:ban sync`) dengan fail-open.
  - [x] Event `BanLifted` + audit siapa yang melakukan unban (`liftedBy`).
- [x] **Artisan CLI Monitoring Ban/Blokir (`guard:ban`)**:
  - [x] Satu command terpadu `php artisan guard:ban {action=list} {subject?}` dengan sub-aksi `list | show | check | stats | unban | sync`.
  - [x] `php artisan guard:ban list` — tabel box-drawing daftar ban/blokir aktif (kolom: `#`, Tipe, Subject, Skor, Sumber, Alasan, Waktu Ban, Sisa TTL) dengan opsi `--type=ip|user`, `--source=`, `--search=`, `--sort=newest|expiring|score`, `--limit=`, dan `--json`.
  - [x] `php artisan guard:ban show {subject}` — tabel detail satu subject: status blokir, skor reputasi, sumber, alasan, IP terkait, waktu ban, sisa TTL, serta status kolom DB untuk user.
  - [x] `php artisan guard:ban check {subject}` — cek cepat apakah IP/user sedang diban/diblokir (✅ AMAN / ⛔ DIBLOKIR + sisa waktu), exit code non-zero bila diblokir (cocok untuk skrip/CI).
  - [x] `php artisan guard:ban stats` — tabel ringkasan total aktif per tipe + tabel proporsi per sumber/detektor dengan bar visual.
  - [x] `php artisan guard:ban unban {subject?}` — buka blokir IP/user langsung (atau pilih dari daftar interaktif bila `{subject}` dikosongkan), mendukung `--sync-db` dan `--force`.
  - [x] Smoke test untuk `BanRegistry` (`block`, `findBan`, `bans`, `unblock`, `unbanUser`).

### 3. Developer Experience
- [x] **Artisan Tooling**: `guard:install` (publish config), `guard:doctor` (cek konfigurasi/store/dataset/Control Plane), `guard:test-rule` (dry-run payload terhadap detektor & profile).
- [x] **Dukungan Versi**: Kompatibilitas Laravel 10/11/12 dan PHP 8.1–8.4 di `composer.json`.
- [x] **Dokumentasi**: Cookbook konfigurasi fleksibel (middleware parameter, `#[GuardProfile]`, `guard:ban`, hooks) di `README.md`.
- [x] **Unit Test**: Cakupan smoke test untuk resolver profile, exclusion multi-dimensi, monitor-only per detektor, event hooks, dan custom detector.

---

## 🐛 Bug & Issue
- [x] **ShipTelemetryCommand & JsonFileVulnerabilityStore Directory Check**: Cegah `ErrorException: file(): Read of 8192 bytes failed with errno=21 Is a directory` saat target berkas buffer atau storage path masih berupa direktori atau belum berbentuk file reguler.

