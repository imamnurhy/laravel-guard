# 🛡️ Panduan Pembuatan & Pengembangan Detector

> Standar implementasi detector keamanan bawaan dan kustom pada package `explorin/laravel-guard`.

---

## 📋 1. Kontrak Detektor (`AppGuard\Core\Contracts\Detector`)

Setiap detektor wajib mengimplementasikan interface:

```php
namespace AppGuard\Core\Contracts;

use AppGuard\Core\RequestContext;
use AppGuard\Core\Signal;

interface Detector
{
    /**
     * Nama unik pengenal detektor (contoh: 'honeypot', 'sqli', 'entropy')
     */
    public function name(): string;

    /**
     * Fase eksekusi: 'pre' (sebelum controller) atau 'post' (setelah controller terminate)
     */
    public function phase(): string;

    /**
     * Evaluasi konteks request dan kembalikan Signal jika mencurigakan, atau null jika bersih
     */
    public function detect(RequestContext $context): ?Signal;
}
```

---

## ⚖️ 2. Standar Pembobotan Skor (`Signal`)

Hindari pemblokiran biner seketika kecuali untuk serangan terkonfirmasi 100%. Gunakan klasifikasi bobot berikut:

| Kategori Skor | Rentang Nilai | Contoh Indikator | Aksi Umum |
|---|:---:|---|---|
| **Kritis (Instant Block)** | 100 | Akses URL Honeypot (`/.env`, `/wp-admin`), SQL Injection terkonfirmasi | Langsung blokir HTTP 403 & catat reputasi IP/User |
| **Tinggi (High Suspicion)** | 50 – 75 | Path traversal (`../`), XSS eksplisit, Brute force IP limit tercapai | Masuk zona kuning; request berikutnya berisiko throttle/block |
| **Sedang (Medium Risk)** | 30 – 45 | Parameter tampering (`c_status`), forced browsing 403/404 POST beruntun | Menambah penalti reputasi pada sliding window |
| **Rendah (Anomaly Signal)** | 15 – 25 | Shannon Entropy teks tidak wajar, header aneh, percobaan IDOR pertama | Penanda awal untuk dikombinasikan dengan sinyal lain |

### Konstruksi Objek `Signal`:
```php
return new Signal(
    detector: $this->name(),
    score: 50,
    description: "Pola serangan XSS terdeteksi pada parameter 'search'",
    persistent: true // Set true jika skor harus diakumulasikan ke cache reputasi penyerang
);
```

---

## 🔬 3. Prinsip Efisiensi Algoritma (Microsecond Budget)

Detektor fase PRE berjalan pada **setiap request masuk**. Oleh karena itu:
1. **Hindari Regex Catastrophic Backtracking**:
   - Selalu batasi panjang string input sebelum menjalankan regex (contoh: `substr($value, 0, 1024)`).
   - Gunakan pencarian string literal (`str_contains`, `str_starts_with`) sebelum menjalankan regex kompleks.
2. **Shannon Entropy untuk Obfuscation Detection**:
   - Hitung nilai entropi $H(X)$ pada teks input: jika panjang $\ge 30$ karakter dan entropi $\ge 4.5$, indikasikan kemungkinan shellcode terenkripsi / base64 payload.
3. **Fail-Fast**:
   - Jika suatu field request kosong atau bertipe numerik, lewati (*early return null*) sebelum memproses regex.
