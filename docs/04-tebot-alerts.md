# 📢 Notifikasi Darurat Telegram (Tebot Notifier)

Panduan konfigurasi dan cara kerja notifikasi darurat keamanan ke Telegram via package `explorin/tebot`.

---

## 1. Cara Kerja & Desain Failsafe

AppGuard terintegrasi dengan **Tebot** untuk mengirim pesan peringatan instan ketika terjadi:
- **Auto-Banned Pengguna** (karena akumulasi pelanggaran IDOR, Tampering, dsb).
- **Serangan Kritis** (misal percobaan SQL Injection eksplisit).

### Prinsip *Graceful Failsafe*:
Package `explorin/laravel-guard` **tidak mewajibkan** `explorin/tebot` sebagai ketergantungan keras (*hard dependency*). 
- Jika proyek Anda telah menginstal `explorin/tebot` dan mengonfigurasi API Key bot Telegram, notifikasi Telegram otomatis terkirim.
- Jika proyek Anda tidak menggunakan Tebot, AppGuard secara otomatis beralih ke standard Laravel Logger (`Log::warning(...)`) tanpa memunculkan exception atau error runtime.

---

## 2. Pengaturan di Aplikasi

Di file `.env`:

```env
# Aktifkan fitur alert Tebot di Guard
GUARD_TEBOT_ENABLED=true

# Pastikan konfigurasi Tebot sudah terisi (jika menggunakan Tebot)
TEBOT_KEY=your_tebot_api_key
```

Di `config/guard.php`:

```php
'tebot' => [
    'enabled' => env('GUARD_TEBOT_ENABLED', true),
],
```

---

## 3. Format Tampilan Pesan di Telegram

Pesan diformat menggunakan HTML cantik dengan detail lengkap insiden:

```text
🚨 [AKUN USER AUTO-BANNED]

• User ID: 1402
• Username: pemohon_testing
• Alasan: Akumulasi skor pelanggaran mencapai 100/100: Percobaan akses berkas milik akun lain (IDOR)
• Endpoint: https://simponie.tangselkota.go.id/permohonan/8921/berkas
• Client IP: 114.122.10.4
• Aksi: Status c_status = 1 & Force Logout
```

---

## 4. Customizing Notifier

Jika Anda ingin mengganti Tebot dengan bot Telegram kustom Anda sendiri, Slack Webhook, atau Discord Webhook, Anda cukup me-listen event `AppGuard\Events\UserBanned` di `EventServiceProvider` aplikasi Anda:

```php
use AppGuard\Events\UserBanned;

Event::listen(UserBanned::class, function (UserBanned $event) {
    // Kirim notifikasi kustom ke Slack / Discord / WhatsApp / Email
    // $event->user;
    // $event->score;
    // $event->reason;
});
```
