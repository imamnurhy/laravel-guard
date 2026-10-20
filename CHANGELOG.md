# 📜 Changelog — Laravel Guard (AppGuard Package)

Dokumen ini mencatat seluruh riwayat rilis, perubahan fitur, perbaikan bug, dan pengujian pada library keamanan `explorin/laravel-guard`. Format mengacu pada prinsip [Keep a Changelog](https://keepachangelog.com/).

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
