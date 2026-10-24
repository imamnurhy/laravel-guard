# 📜 Changelog — Laravel Guard (AppGuard Package)

Dokumen ini mencatat seluruh riwayat rilis, perubahan fitur, perbaikan bug, dan pengujian pada library keamanan `explorin/laravel-guard`. Format mengacu pada prinsip [Keep a Changelog](https://keepachangelog.com/).

---

## [2026-10-24]

### Added
- **Multi-Driver Telemetry & Incident Store (`redis`, `cache`, `jsonl`, `array`, `null`)** ([VulnerabilityStore.php](./src/Core/Contracts/VulnerabilityStore.php), [RedisVulnerabilityStore.php](./src/Stores/RedisVulnerabilityStore.php), [CacheVulnerabilityStore.php](./src/Stores/CacheVulnerabilityStore.php), [JsonFileVulnerabilityStore.php](./src/Stores/JsonFileVulnerabilityStore.php), [guard.php](./config/guard.php), [GuardServiceProvider.php](./src/GuardServiceProvider.php)):
  - Abstraksi penyimpanan buffer telemetri insiden keamanan multi-driver yang dapat dipilih melalui konfigurasi tunggal `GUARD_TELEMETRY_DRIVER` atau `GUARD_STORE`.
  - Penambahan kontrak antrean batch (`pullBatch(int $limit = 100): array`, `count(): int`) pada `VulnerabilityStore`.
  - Driver `redis` berbasis atomic operations (`RPUSH`, `LRANGE`, `LTRIM`) dengan batasan kapasitas antrean `max_items`.
  - Driver `cache` berbasis ring-buffer array terbatasi dengan masa retensi TTL.
  - Refactor command `php artisan guard:ship-telemetry` ([ShipTelemetryCommand.php](./src/Console/ShipTelemetryCommand.php)) dengan dukungan opsi `--clear [--force]` untuk mengosongkan buffer telemetri aktif lintas driver.
  - Perbaruan `php artisan guard:doctor` ([DoctorCommand.php](./src/Console/DoctorCommand.php)) untuk memeriksa kesiapan dan integritas store telemetri aktif.
- **Fitur Massal Clear / Flush Ban (`guard:ban clear`)** ([Guard.php](./src/Core/Guard.php), [BanRegistry.php](./src/Core/Contracts/BanRegistry.php), [CacheBanRegistry.php](./src/Stores/CacheBanRegistry.php), [ArrayBanRegistry.php](./src/Core/Stores/ArrayBanRegistry.php), [BanCommand.php](./src/Console/BanCommand.php)):
  - Method `Guard::clearBans(?string $type = null, string $liftedBy = 'cli', string $reason = 'Bulk clear'): int` untuk membuka seluruh blokir aktif (IP dan/atau User) secara massal, membersihkan key cache store, skor reputasi, force logout, serta menembakkan event `BanLifted`.
  - Sub-command CLI `php artisan guard:ban clear` (alias `flush` atau `guard:ban unban --all`) dengan dukungan opsi `--type=ip|user`, `--sync-db`, `--force`, dan `--json` beserta konfirmasi jumlah entri dan tabel ringkasan eksekusi.
- **Built-in Security Response Views & Custom Error Presentation** ([blocked.blade.php](./resources/views/blocked.blade.php), [throttled.blade.php](./resources/views/throttled.blade.php), [GuardServiceProvider.php](./src/GuardServiceProvider.php), [GuardMiddleware.php](./src/Http/GuardMiddleware.php), [guard.php](./config/guard.php)):
  - Halaman respons visual profesional bawaan library untuk HTTP 403 (`guard::blocked`) dan HTTP 429 (`guard::throttled`) dengan desain modern, informasi insiden yang aman, countdown `Retry-After`, dan opsi override ke custom view aplikasi host via `guard.responses.views`.
  - Deteksi peramban web otomatis pada `GuardMiddleware::reject()` agar merender HTML view untuk request browser non-JSON dan tetap merespons JsonResponse untuk request API/AJAX.
- **Standardisasi Output Tabel Terminal Bergaya Box-Drawing (`TableStyle`)** ([StatusCommand.php](./src/Console/StatusCommand.php), [UserStatusCommand.php](./src/Console/UserStatusCommand.php), [BanCommand.php](./src/Console/BanCommand.php)):
  - Format tabel visual terstruktur, badge warna status, dan konsistensi header box-drawing pada seluruh perintah CLI inspeksi (`guard:status`, `guard:user-status`, `guard:ban list`).
  - Penambahan opsi `--json` pada `guard:status` dan `guard:user-status` untuk kemudahan otomasi monitoring dan skrip healthcheck.
- **Otomatisasi Eksekusi Banned IPs dari Snapshot Control Plane** ([SyncCommand.php](./src/Console/SyncCommand.php)):
  - Iterasi array `banned_ips` dari snapshot dan eksekusi langsung ke `$guard->block($ip, $banDuration, ...)` sehingga key individual `block:ip:{ip}` aktif di Redis/Cache Store dan tercatat di `BanRegistry`.
  - Mekanisme **auto-unblock** (`$guard->unblock()`) otomatis untuk IP yang telah dicabut dari snapshot Control Plane.
  - Penggunaan masa ban (TTL) terkonfigurasi dari `config('guard.ip_ban.duration', 86400)` untuk mencegah memory leak dan false-positive pada IP dinamis.
  - Penambahan eksekusi blokir IP snapshot pada fungsi `loadFallbackSnapshot()` saat Control Plane offline atau Circuit Breaker terbuka.
  - Refresh perpanjangan TTL masa ban pada Redis saat respons sinkronisasi menerima status HTTP 304 (Not Modified).
- **Pertahanan Berlapis (*Defense-in-Depth*) di Fase Inspeksi** ([Guard.php](./src/Core/Guard.php)):
  - Menambahkan inspeksi langsung ke cache array `guard:{$tenant}:banned_ips` pada `Guard::inspect()` sebagai proteksi fail-safe instan di level middleware.

### Fixed
- **Fallback App Key Webhook Controller** ([WebhookController.php](./src/Http/WebhookController.php)):
  - Menambahkan fallback `config('guard.control_plane.app_key')` jika header `X-Guard-App-Key` tidak terkirim agar namespace cache tenant tidak rusak (`guard::banned_ips`).
- **Testing & Validasi**:
  - Validasi sintaksis `php -l` pada seluruh berkas yang dimodifikasi (lolos 100%).
  - Uji sinkronisasi CLI `php artisan guard:sync --force` dan verifikasi monitor `php artisan guard:ban`.
  - Simulasi request HTTP real dari IP blacklist menghasilkan HTTP 403 (Akses Dibatasi).

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
