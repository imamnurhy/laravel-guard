# 🏛️ Arsitektur & Desain Teknis — AppGuard (`explorin/laravel-guard`)

Dokumen ini menjelaskan arsitektur internal, alur eksekusi request, modul-modul utama, serta integrasi komponen `app-guard`.

---

## 🧭 1. Gambaran Umum & Filosofi Desain

AppGuard dirancang dengan prinsip:
1. **Scoring-Based (Bukan Binary Block):** Setiap indikator kecurigaan menyumbang poin penalti (`Signal`). Pemblokiran atau pembatasan dilakukan berdasarkan akumulasi skor dalam sliding window waktu.
2. **Framework-Agnostic Core:** Logika bisnis pemeriksaan, kalkulasi skor, dan pemilihan aksi berada di namespace `AppGuard\Core` (POPO / Plain Old PHP Objects), tanpa ketergantungan pada Laravel. Ini membuat core stateless, sangat cepat, dan aman untuk runtime asinkron seperti Laravel Octane.
3. **Defense-in-Depth (Dua Fase: PRE & POST):**
   - **Fase PRE:** Memeriksa perimeter request (IP, path, query, honeypot, token) sebelum menyentuh controller aplikasi.
   - **Fase POST:** Mengobservasi response controller (HTTP status 403, 404, exception) dan memperbarui reputasi penyerang untuk request berikutnya.
4. **Autonomous Domain Protection:** Mampu memblokir akun pengguna di level basis data (`user_ban`) dan memutus sesi seketika saat terdeteksi pelanggaran logika bisnis seperti IDOR.
5. **Continuous Feedback / ML-Ready:** Merekam setiap celah atau bypass yang terkonfirmasi ke dalam media log JSONL terstruktur sebagai bahan pembelajaran mesin.

---

## 📐 2. Diagram Alur Eksekusi (Request Lifecycle)

```
[ Request Masuk dari Klien ]
             │
             ▼
[ TrustProxies / IP Normalizer ]
             │
             ▼
[ AppGuard\Http\GuardMiddleware ] ── (Fase PRE: handle)
             │
             ├── 1. Whitelist Check (IP / Safe Route) ──► [ Langsung Lolos ]
             ├── 2. IP Manual Blocklist Check ──────────► [ Tolak HTTP 403 ]
             ├── 3. User Banned Check (c_status / DB) ──► [ Force Logout & 403 ]
             │
             ├── 4. Eksekusi Detectors (PRE):
             │      ├── HoneypotDetector (Path & Form Field Trap)
             │      ├── PathTraversalDetector (../, ..\, %00)
             │      ├── MaliciousPayloadDetector (SQLi, XSS)
             │      ├── ParameterTamperingDetector (Injeksi field dilarang)
             │      ├── AnomalyDetector (Shannon Entropy)
             │      └── BruteForceDetector (Ambang IP / Identifier)
             │
             ├── 5. Hitung Skor = Reputasi + Sinyal Baru
             │      ├── Skor >= Block (100)   ──► [ Tolak HTTP 403 ] + (Auto-Banned User jika login)
             │      ├── Skor >= Throttle (50) ──► [ Batasi HTTP 429 Retry-After ]
             │      └── Skor Wajar             ──► [ Lanjutkan Request ]
             ▼
[ Controller & Logika Bisnis Aplikasi ]
             │
             ├── Jika Controller mendeteksi IDOR / Akses Tidak Sah:
             │   SecurityGuard::recordViolation($user, 'idor', 25)
             │   └── Jika Skor User >= 100 ──► Auto-Banned Database & Tebot Telegram Alert
             │
             ▼
[ Response Terbentuk (HTTP Status Code) ]
             │
             ▼
[ GuardMiddleware::terminate() ] ── (Fase POST)
             │
             ├── 1. DeniedAccessDetector: Hitung frekuensi 403 / 404 beruntun
             ├── 2. AnomalyDetector: Evaluasi URL Scanner / Fuzzing masif
             └── 3. VulnerabilityStore: Catat insiden ke `vulnerabilities.jsonl`
```

---

## 🧩 3. Komponen & Struktur Namespace

### A. Namespace `AppGuard\Core` (Independen Framework)
- **`Guard`**: Mesin orkestrator utama yang menjalankan detector, mengelola store cache, menghitung reputasi, dan mengambil keputusan.
- **`RequestContext`**: DTO request ternormalisasi (IP, method, path, user agent, user ID, inputs).
- **`Signal`**: Representasi penalti dari detector (nama detector, skor, deskripsi, flag persistensi).
- **`Decision`**: Hasil evaluasi akhir (`Action::Allow`, `Action::Throttle`, `Action::Block`).
- **`Contracts\Detector`**: Antarmuka standar bagi semua detector PRE & POST.
- **`Contracts\Store`**: Antarmuka abstraksi cache untuk counter skor reputasi.
- **`Contracts\VulnerabilityStore`**: Antarmuka perekaman celah keamanan.

### B. Komponen Adapter Laravel (`src/`)
- **`GuardServiceProvider`**: Registrasi singleton container, pembaca konfigurasi `config/guard.php`, auto-injection middleware kernel, dan event listener autentikasi.
- **`Http\GuardMiddleware`**: Middleware global yang mengapit eksekusi aplikasi (handle & terminate).
- **`Handlers\DefaultUserBanHandler`**: Pelaksana mutasi status database (`c_status = 1`), pembersihan session, dan redirection login.
- **`Notifications\TebotNotifier`**: Layanan integrasi pesan darurat Telegram via package Tebot dengan fallback ke standard logger.
- **`Stores\JsonFileVulnerabilityStore`**: Implementasi penyimpanan celah terstruktur dalam file baris JSONL.
- **`Facades\SecurityGuard`**: Gerbang akses statis yang ramah developer untuk dipanggil di controller atau middleware lain.

---

## 🛡️ 4. Spesifikasi Detektor Bawaan

| Nama Detector | Fase | Deskripsi & Indikator Deteksi | Bobot Default |
|---|:---:|---|:---:|
| `HoneypotDetector` | PRE | Mengakses URL jebakan scanner (`/.env`, `/wp-admin`, `phpmyadmin`, `backup.sql`) atau mengisi field formulir tersembunyi (*honeypot trap*). | 100 (Block Langsung) |
| `BruteForceDetector` | PRE / Event | Melacak kegagalan login pada event `Illuminate\Auth\Events\Failed` per IP, per akun, dan per pasangan IP+Akun. | 60 s/d 100 |
| `PathTraversalDetector` | PRE | Pola escape direktori (`../`, `..\`, `%2e%2e`, `%00`, `/etc/passwd`, `C:\windows`). | 50 |
| `MaliciousPayloadDetector` | PRE | Pola eksploitasi SQL Injection terarah (`union select`, `information_schema`, `sleep()`) dan XSS eksplisit (`<script>`, `onerror=`, `onload=`). | SQLi: 100, XSS: 50 |
| `ParameterTamperingDetector` | PRE | Injeksi parameter terlarang pada mutasi POST/PUT (`c_status`, `is_admin`, `role_id`). | 35 |
| `AnomalyDetector (Entropy)` | PRE | Algoritma Shannon Entropy untuk mendeteksi payload teks dengan keacakan tidak wajar ($H(X) \ge 4.5$) seperti obfuscated shellcode / cipher. | 35 |
| `DeniedAccessDetector` | POST | Akumulasi respon HTTP 403 / 404 berulang kali dari IP yang sama dalam window 60 detik (Forced Browsing). | 40 |
| `AnomalyDetector (Fuzzing)` | POST | Pemindaian masif URL berbeda ($\ge 15$ endpoint 404 dalam 30 detik). | 50 |

---

## 🔔 5. Mekanisme Notifikasi Telegram (Tebot)

Ketika terjadi pemblokiran akun otomatis atau skor pelanggaran mencapai level kritis:
1. `DefaultUserBanHandler` memanggil `TebotNotifier::sendAlert()`.
2. Notifier memeriksa ketersediaan kelas `Explorin\Tebot\Services\Tebot` dan konfigurasi `guard.tebot.enabled`.
3. Format pesan yang dikirim ke Telegram:
   ```html
   🚨 [AKUN USER AUTO-BANNED]

   • User ID: 1402
   • Username: pemohon_nakal
   • Alasan: Percobaan akses tidak sah pada data/berkas milik akun lain (IDOR)
   • Endpoint: https://simponie.tangselkota.go.id/permohonan/8921/berkas
   • Client IP: 114.122.10.4
   • Aksi: Status c_status = 1 & Force Logout
   ```
4. Jika Tebot tidak aktif atau gagal mengirim, sistem menggunakan *failsafe* dengan mencatat error ke channel log tanpa menghentikan pemblokiran.

---

## 📋 6. Log Insiden & Dataset Forensik

Lihat dokumen lengkap mengenai dataset insiden dan analisis forensik di [`docs/06-incident-dataset.md`](./docs/06-incident-dataset.md).
