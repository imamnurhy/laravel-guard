# 📜 Changelog — Laravel Guard (AppGuard Package)

Dokumen ini mencatat seluruh riwayat rilis, perubahan fitur, perbaikan bug, dan pengujian pada library keamanan `explorin/laravel-guard`. Format mengacu pada prinsip [Keep a Changelog](https://keepachangelog.com/).

---

## [2026-10-23]

### Added
- **Profile Preset & Per-Route Security Configuration** ([Guard.php](./src/Core/Guard.php), [GuardProfile.php](./src/Attributes/GuardProfile.php), [guard.php](./config/guard.php)):
  - Parameter middleware fleksibel (`guard:waf,threshold=50`, `guard:strict`, `guard:bypass`) dan PHP Attribute `#[GuardProfile('strict')]` pada controller / action method.
  - Preset profil bawaan (`strict`, `balanced`, `monitor`) yang dapat di-override sebagian (*deep merge*) via config.
  - Dukungan mode `monitor-only` per detektor (`detectors.{name}.monitor_only`) untuk observasi tanpa blokir langsung.
- **Pluggable Architecture & Custom Detector API** ([Guard.php](./src/Core/Guard.php), [Detector.php](./src/Core/Contracts/Detector.php), [guard.php](./config/guard.php)):
  - Kontrak detektor pluggable `Detector` beserta method `Guard::addDetector()` dan registrasi otomatis melalui konfigurasi `guard.custom_detectors`.
  - Pengecualian fleksibel multi-dimensi (`guard.exclusions`) berdasarkan IP/CIDR, pola path wildcard, nama input formulir, header request, serta user/role.
  - Driver pluggable untuk penyimpanan telemetri/kerentanan (`jsonl`, `array`, `null`) via `VulnerabilityStore`.
- **Ban Management & Control Plane Sync (`BanRegistry`)** ([Guard.php](./src/Core/Guard.php), [BanRegistry.php](./src/Core/Contracts/BanRegistry.php), [CacheBanRegistry.php](./src/Stores/CacheBanRegistry.php), [BanRecord.php](./src/Core/BanRecord.php)):
  - Indeks ban terpusat pada Redis/Cache key `guard:bans:index` dengan metadata lengkap (`BanRecord`) untuk listing cepat tanpa operasi scan yang mahal.
  - Metode `Guard::bans()`, `Guard::findBan()`, `Guard::unblock()`, dan `Guard::unbanUser()`.
  - Event payload lengkap untuk `IpBlocked`, `UserBanned`, `BanLifted` beserta audit `liftedBy` dan callback extensibility (`onBan`, `onBanLifted`, `onIncident`, `onScored`).
  - Command CLI terpadu `php artisan guard:ban {action=list} {subject?}` ([BanCommand.php](./src/Console/BanCommand.php)) dengan sub-aksi `list`, `show`, `check`, `stats`, `unban`, dan `sync`.
- **Developer Tooling**:
  - Command `guard:install` untuk publish konfigurasi, `guard:doctor` untuk audit status konfigurasi/cache/store, serta `guard:test-rule` untuk pengujian dry-run detektor.

### Fixed
- **IP Block Auto-Registration & Reputation Visibility** ([Guard.php](./src/Core/Guard.php), [StatusCommand.php](./src/Console/StatusCommand.php), [BanCommand.php](./src/Console/BanCommand.php), [guard.php](./config/guard.php)):
  - Auto-record pemblokiran IP ke `BanRegistry` (`BanRecord` tipe IP) saat request menghasilkan `Action::Block` pada fase inspeksi profil `strict` (seperti `/login`).
  - Penyempurnaan `Guard::isBlocked($ip)` untuk memeriksa apakah skor reputasi IP saat ini mencapai atau melampaui ambang batas blokir (`thresholds.block` atau profil `strict`), bukan hanya mengecek key blokir manual.
  - Penyempurnaan `guard:status` dan `guard:ban` agar menampilkan status blokir, threshold pembanding, dan indikator yang akurat tanpa false "AMAN/AKTIF" saat IP terblokir.
  - Konfigurasi `ip_ban` (`enabled`, `duration`) di `config/guard.php`.
- **Testing**:
  - Penambahan dan pembaruan cakupan pengujian di [smoke.php](./tests/smoke.php) (seluruh 58 tests passed).

---

## [2026-10-19]

### Added
- **Core Security & Management**: Method inti unban dan inspeksi status pengguna pada core Guard ([Guard.php](./src/Core/Guard.php), [SecurityGuard.php](./src/Facades/SecurityGuard.php), [DefaultUserBanHandler.php](./src/Handlers/DefaultUserBanHandler.php)):
  - Menambahkan method `unbanUser(string|int $userId)` untuk membersihkan key cache `block:user:`, `guard:user_banned:`, `score:user:`, dan `force_logout:user:`.
  - Menambahkan method `isUserBanned(string|int $userId): bool` dan `isUserForceLoggedOut(string|int $userId): bool`.
  - Menambahkan dukungan `unban($user, bool $syncDb = false)` pada `DefaultUserBanHandler`.
- **Artisan Console Commands**: Rangkaian command CLI manajemen keamanan pengguna ([GuardServiceProvider.php](./src/GuardServiceProvider.php)):
  - `php artisan guard:unban-user {userId} {--sync-db}` ([UnbanUserCommand.php](./src/Console/UnbanUserCommand.php)): Membuka blokir pengguna di layer cache dan opsional menyinkronkan status database ke aktif.
  - `php artisan guard:user-status {userId}` ([UserStatusCommand.php](./src/Console/UserStatusCommand.php)): Menampilkan status blokir, skor penalti akumulatif, dan status database pengguna.
  - `php artisan guard:ban-user {userId} {--reason=}` ([BanUserCommand.php](./src/Console/BanUserCommand.php)): Memblokir pengguna secara manual via CLI console.
- **Testing**: Penambahan test case unban dan inspeksi status pengguna di [smoke.php](./tests/smoke.php) (32 tests passed).

### Fixed
- **CLI & Storage Directory Check** ([ShipTelemetryCommand.php](./src/Console/ShipTelemetryCommand.php), [JsonFileVulnerabilityStore.php](./src/Stores/JsonFileVulnerabilityStore.php)):
  - Menambahkan pengecekan eksplisit `!is_dir($filePath)` / `!File::isDirectory(...)` sebelum fungsi `file()` dipanggil.
  - Mengatasi `ErrorException: file(): Read of 8192 bytes failed with errno=21 Is a directory` yang terjadi di production jika target path masih berupa direktori atau file reguler belum terbentuk.
- **CLI Robustness**: Parameter `{ip?}` dibuat opsional pada command `guard:status` ([StatusCommand.php](./src/Console/StatusCommand.php)):
  - Mencegah insiden `RuntimeException: Not enough arguments (missing: "ip")` saat command dijalankan tanpa argumen oleh scheduler, healthcheck, atau sysadmin.
  - Menampilkan ringkasan status operasional global sistem AppGuard saat parameter `{ip}` tidak disertakan.
