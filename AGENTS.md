# 📚 Panduan AI Assistant & Developer — AppGuard (`explorin/laravel-guard`)

> Dokumen ini adalah pedoman operasional, standar desain, dan batasan teknis (guardrails) bagi AI Assistant, Agent, dan Developer yang berinteraksi dengan codebase `explorin/laravel-guard`.

---

## 🧭 1. Konteks Proyek

- **Fungsi Package:** Application-Level Security Guard, Scoring-Based WAF, Domain Logic Guard (Anti-IDOR & Auto-Banned), dan Vulnerability Dataset Capture (JSONL) untuk ekosistem Laravel & PHP.
- **Runtime & Bahasa:** PHP >= 8.1, kompatibel dengan Laravel 10 & 11, serta arsitektur asinkron (Laravel Octane).
- **Filosofi Arsitektur:**
  - **Framework-Agnostic Core (`AppGuard\Core`)**: Seluruh logika evaluasi, kalkulasi Shannon Entropy, pembobotan skor, dan pemilihan aksi dibangun menggunakan Plain Old PHP Objects (POPO) tanpa dependensi Laravel. Stateless, instan (< 1ms), dan aman untuk Octane.
  - **Laravel Adapter (`src/`)**: Jembatan integrasi Laravel (Service Provider, Facade `SecurityGuard`, Middleware, Handler User Banned, Notifier Tebot Telegram, dan Artisan CLI).
- **Two-Phase Lifecycle (PRE & POST)**:
  - *Fase PRE (`handle`)*: Memeriksa perimeter request (Honeypot, Traversal, SQLi, XSS, Tampering, Entropy) sebelum menyentuh controller aplikasi host.
  - *Fase POST (`terminate`)*: Mengobservasi respon controller (Denied Access 403/404, Forced Browsing, Scanner Fuzzing) dan mencatat insiden ke `vulnerabilities.jsonl`.

---

## ⛔ 2. Batasan & Perintah yang Dilarang (Guardrails)

1. **Prinsip Failsafe (Fail-Open / Non-Breaking Host)**:
   - Security guard **DILARANG KERAS** mematikan atau membuat aplikasi host mengalami *fatal error / crash 500* hanya karena cache (Redis/Memcached) down atau ada exception pada detector.
   - Jika terjadi kegagalan internal store/cache, guard wajib melakukan *fail-open* (meloloskan request dengan mencatat log peringatan).
2. **Isolasi Core POPO**:
   - Dilarang mengimpor facade Laravel (`Illuminate\Support\Facades\...`) atau fungsi helper framework (`request()`, `config()`, `auth()`, `app()`) ke dalam namespace `AppGuard\Core`.
   - Core harus tetap murni PHP tanpa dependensi framework luar.
3. **Kompatibilitas Laravel Octane (State Safety)**:
   - Dilarang menyimpan state request per user pada properti statis singleton yang dapat mencemari (*memory leak / cross-tenant pollution*) request berikutnya di runtime Octane.
4. **Kontrol Git**:
   - Dilarang menjalankan `git commit`, `git push`, `git reset`, atau `git stash` tanpa instruksi eksplisit dari pengguna.

---

## 🛠️ 3. Pedoman Pengkodean & Arsitektur

### A. Detektor Berbasis Skor (Scoring, Bukan Binary If-Else)
- Setiap detektor mengembalikan objek `AppGuard\Core\Signal` berisi bobot skor kecurigaan (0 s/d 100), nama detektor, dan deskripsi temuan.
- Keputusan pemblokiran (`Action::Block` / HTTP 403) atau pembatasan (`Action::Throttle` / HTTP 429) ditentukan oleh akumulasi skor total dalam sliding window waktu, bukan blokir kaku seketika (kecuali pelanggaran kritis seperti Honeypot atau SQLi terkonfirmasi).

### B. Business Logic Guard & Anti-IDOR
- Sediakan akses statis ramah pengembang via `SecurityGuard::recordViolation($user, $type, $score, $reason)`.
- Jika pelanggaran user mencapai ambang batas (`threshold = 100`), delegasikan ke `UserBanHandler` untuk memutasi kolom status basis data (default: `c_status = 1`), membersihkan sesi login (*force logout*), memicu event `UserBanned`, dan mengirim notifikasi darurat.

### C. Perekaman Forensik Dataset (`VulnerabilityStore`)
- Celah keamanan atau percobaan bypass yang terdeteksi wajib disimpan dalam format baris JSONL (`vulnerabilities.jsonl`) secara efisien untuk bahan audit forensik dan pelatihan model Machine Learning.

---

## 🔄 4. Siklus Pengujian & Validasi

Sebelum menandai pekerjaan selesai:
1. Jalankan syntax check: `php -l <file>`.
2. Jalankan smoke test mandiri: `php tests/smoke.php` (memastikan seluruh 19/19 checks lolos 100%).
3. Jalankan test suite PHPUnit: `./vendor/bin/phpunit` (jika dependensi vendor terinstal).
4. Pastikan tidak ada pelanggaran tipe strict PHP (`declare(strict_types=1);`).
5. Perbarui dokumentasi di [`CHANGELOG.md`](./CHANGELOG.md) dan tandai backlog di [`TODO.md`](./TODO.md).

---

## 📚 5. Modular Knowledge Base (`.agents/` Directory)

Untuk panduan mendalam arsitektur dan integrasi AppGuard:

### A. Aturan Sistem (`.agents/rules/`)
- [`.agents/rules/ARCHITECTURE-AND-CORE-PRINCIPLES.md`](.agents/rules/ARCHITECTURE-AND-CORE-PRINCIPLES.md) — Desain POPO Core vs Adapter Laravel, siklus PRE & POST, dan Octane state safety.
- [`.agents/rules/DETECTOR-DEVELOPMENT-GUIDELINES.md`](.agents/rules/DETECTOR-DEVELOPMENT-GUIDELINES.md) — Standar pembuatan detector baru, pembobotan skor, dan algoritma Shannon Entropy.
- [`.agents/rules/FAILSAFE-AND-PERFORMANCE-STANDARDS.md`](.agents/rules/FAILSAFE-AND-PERFORMANCE-STANDARDS.md) — Standar fail-open, toleransi kegagalan cache, dan eksekusi non-blocking mikrodetik.

### B. Keterampilan & Boilerplate Integrasi (`.agents/skills/`)
- [`.agents/skills/guard-integration/`](.agents/skills/guard-integration/) — Panduan & boilerplate integrasi AppGuard ke aplikasi host Laravel (IDOR mitigation, custom ban handler, dan Tebot alerts) (lihat [EXAMPLE.md](.agents/skills/guard-integration/EXAMPLE.md)).
- [`.agents/skills/custom-detector-builder/`](.agents/skills/custom-detector-builder/) — Panduan & boilerplate pembuatan detektor keamanan kustom berbasis kontrak `AppGuard\Core\Contracts\Detector`.
