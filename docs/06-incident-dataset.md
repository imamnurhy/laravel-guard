# 📋 Log Insiden & Dataset Forensik Keamanan (Incident Forensics)

Dokumen ini menjelaskan mekanisme bagaimana `app-guard` mencatat insiden keamanan (*incident footprint*) dan celah terekspose ke dalam format terstruktur (*JSON Lines*), kegunaannya untuk audit dan analisis forensik, serta roadmap pemanfaatannya di masa depan.

---

## 🎯 1. Konsep Utama: Forensik & Rekaman Insiden Nyata

Ketika request diproses, ada dua sumber deteksi insiden dalam sistem:
1. **Insiden di Lapisan Perimeter (WAF / Middleware):**
   Terjadi saat detektor mendeteksi anomali seperti SQL Injection, Path Traversal, Brute Force, atau Probing Scanner.
2. **Insiden di Lapisan Aplikasi (Controller / Domain Logic):**
   Terjadi saat penyerang lolos dari filter perimeter awal, namun tertangkap oleh kontrol otorisasi aplikasi (contoh: IDOR pada berkas permohonan, bypass CAPTCHA, atau manipulasi parameter). Pada tahap ini, aplikasi memanggil `SecurityGuard::recordViolation(...)`.

**Tujuan Pencatatan Insiden (`JsonFileVulnerabilityStore`):**
- **Bukti Forensik Utuh:** Menyimpan anatomi request (IP, User ID, HTTP Method, Path, Payload parameter, status respon, serta alasan pelanggaran).
- **Audit & Penyelidikan:** Mengetahui siapa, kapan, dan endpoint mana yang sedang dieksploitasi tanpa harus membedah log mentah server berukuran gigabyte.
- **Tuning Ambang Batas (Rule Calibration):** Membantu administrator mengevaluasi apakah ada *false positive* atau aturan yang perlu diperketat.

---

## 🗄️ 2. Struktur Penyimpanan Dataset (`vulnerabilities.jsonl`)

File dataset disimpan secara default pada:
```
storage/app/guard/vulnerabilities.jsonl
```

Format penyimpanan menggunakan **JSON Lines (JSONL)** di mana setiap baris adalah satu objek JSON valid. Keuntungan format ini:
- **Append-only efisien:** Proses penulisan tidak memuat/membaca seluruh isi file, sangat cepat dan hemat memori pada server produksi.
- **Mudah dianalisis:** Dapat langsung diparsing menggunakan CLI (`jq`, `grep`, `awk`), log viewer, maupun data tools (Python `pandas.read_json(..., lines=True)`).

### Contoh Entri Insiden JSONL:

#### A. Pelanggaran Tingkat Aplikasi (Contoh: IDOR)
```json
{
  "type": "application_violation",
  "severity": "critical",
  "rule_key": "idor",
  "points": 25,
  "ip": "114.122.10.4",
  "user_id": "1402",
  "method": "GET",
  "path": "/permohonan/8921/berkas",
  "payload": {
    "syarat_id": "10492",
    "filter": "all"
  },
  "response_status": 403,
  "reasons": [
    "Percobaan akses tidak sah pada data/berkas milik akun lain (IDOR)"
  ],
  "timestamp": "2026-10-14 20:05:00"
}
```

#### B. Pelanggaran Tingkat Perimeter (Contoh: Scanner / Fuzzing)
```json
{
  "type": "post_observation",
  "severity": "high",
  "rule_key": "scanner_fuzzing",
  "points": 50,
  "ip": "45.12.89.1",
  "user_id": null,
  "method": "GET",
  "path": "/api/v1/debug_panel",
  "payload": {},
  "response_status": 404,
  "reasons": [
    "anomaly: massive scanner/fuzzing detected (18 distinct paths in 30s)"
  ],
  "timestamp": "2026-10-14 20:06:12"
}
```

---

## 🔍 3. Cara Memeriksa Log Insiden

### Menggunakan Command Line (`jq` / Linux Shell):
```bash
# Menampilkan 5 insiden terakhir secara rapi:
tail -n 5 storage/app/guard/vulnerabilities.jsonl | jq .

# Menghitung insiden berdasarkan jenis pelanggaran:
cat storage/app/guard/vulnerabilities.jsonl | jq -r '.rule_key' | sort | uniq -c | sort -nr

# Melihat daftar IP penyerang paling agresif:
cat storage/app/guard/vulnerabilities.jsonl | jq -r '.ip' | sort | uniq -c | sort -nr
```

---

## 🔮 4. Roadmap & Rencana Pengembangan Lanjutan (Eksplorasi AI/ML)

> ⚠️ **Catatan Status:** Saat ini AppGuard bekerja murni berbasis **Aturan Heuristik & Scoring Dinamis**, bukan model Machine Learning yang berjalan otomatis (*no real-time neural inference*).

Dataset insiden JSONL ini disiapkan agar di masa depan dapat dijadikan sebagai *ground truth dataset* untuk penelitian dan peningkatan keamanan otomatis:

1. **Analisis Klaster Pola Serangan (Offline Clustering):**
   Menggunakan algoritma seperti TF-IDF dan Isolation Forest / DBSCAN untuk memetakan variasi serangan baru yang belum memiliki signature regex.
2. **Umpan Balik ke Custom Detector:**
   Jika ditemukan pola serangan berulang, administrator atau tim security dapat membuat `CustomDetector` baru yang mengimplementasikan `AppGuard\Core\Contracts\Detector` dan mendaftarkannya pada `config/guard.php`:
   ```php
   'custom_detectors' => [
       App\Security\Detectors\CustomPatternDetector::class,
   ],
   ```
3. **Penyusutan & Rotasi Data:**
   Disarankan menerapkan rotasi berkas (misal `logrotate` mingguan atau bulanan) agar file `vulnerabilities.jsonl` tidak membesar tanpa batas di server produksi.
