# 🏛️ Arsitektur & Prinsip Inti AppGuard

> Pedoman arsitektur sistem, pemisahan lapisan logika, dan siklus hidup request pada package `explorin/laravel-guard`.

---

## 🧭 1. Pemisahan Tegas Dua Lapisan (Two-Tier Separation)

```
┌─────────────────────────────────────────────────────────────┐
│             Tier 1: Core Engine (AppGuard\Core)             │
│                                                             │
│   • POPO (Plain Old PHP Objects) murni                      │
│   • 100% Framework-Agnostic (Bebas dependensi Laravel)      │
│   • Stateless & Thread-Safe (Laravel Octane Ready)          │
│   • Komponen: Guard, Signal, Decision, RequestContext,      │
│               Contracts (Detector, Store, VulnStore)        │
└──────────────────────────────┬──────────────────────────────┘
                               │ (Diadaptasi & Diorkestrasi)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             Tier 2: Laravel Adapter (AppGuard\...)          │
│                                                             │
│   • GuardServiceProvider & SecurityGuard Facade             │
│   • GuardMiddleware (PRE handle & POST terminate)           │
│   • Stores: LaravelCacheStore, JsonFileVulnerabilityStore   │
│   • Handlers: DefaultUserBanHandler (DB c_status & Logout)  │
│   • Notifiers: TebotNotifier (Telegram Alerts)              │
│   • Artisan Commands: guard:status, block, unblock          │
└─────────────────────────────────────────────────────────────┘
```

### Aturan Batasan Lapisan:
- Kode di dalam namespace `AppGuard\Core` **TIDAK BOLEH** mengetahui keberadaan Laravel, Eloquent, Facade, Session, atau Helper framework.
- Seluruh interaksi dengan framework wajib melalui adapter interface (`Contracts\Store`, `Contracts\Detector`, `Contracts\UserBanHandler`).

---

## ⚡ 2. Dua Fase Pemeriksaan (Defense-in-Depth Lifecycle)

1. **Fase PRE (`GuardMiddleware::handle`)**:
   - Dijalankan **sebelum** request menyentuh routing atau controller aplikasi host.
   - Bertugas memfilter perimeter:
     - Pemeriksaan whitelist (IP tepercaya / safe path bypass).
     - Pemeriksaan blacklist IP manual.
     - Pemeriksaan status user banned (`c_status = 1` / blacklist session).
     - Eksekusi detektor PRE (Honeypot, Path Traversal, Malicious Payload SQLi/XSS, Parameter Tampering, Shannon Entropy, Brute Force).
   - Menghasilkan keputusan instan: `Allow` (lanjutkan), `Throttle` (HTTP 429), atau `Block` (HTTP 403).

2. **Fase POST (`GuardMiddleware::terminate`)**:
   - Dijalankan **setelah** response dikirimkan ke klien (di latar belakang).
   - Mengobservasi respons aplikasi host:
     - `DeniedAccessDetector`: Menghitung frekuensi status HTTP 403 dan 404 berulang kali dalam kurun 60 detik (Forced Browsing / Directory Bruteforce).
     - `AnomalyDetector (Fuzzing)`: Mendeteksi pemindaian endpoint masif.
     - `VulnerabilityStore`: Menuliskan log temuan celah keamanan ke file dataset `vulnerabilities.jsonl`.

---

## 🚀 3. Kompatibilitas Laravel Octane & High-Concurrency

1. **Stateless Request Execution**:
   - Instance `AppGuard\Core\Guard` tidak boleh menyimpan objek request atau data user pada properti internal yang persisten antar request.
   - Setiap pemanggilan metode `evaluate(RequestContext $context)` menerima DTO baru dan mengembalikan `Decision` murni.
2. **Atomic Store Increments**:
   - Penghitungan skor akumulasi reputasi dilakukan secara atomik pada cache backend (Redis / Memcached) dengan waktu hidup (*TTL / sliding window*) terkontrol.
