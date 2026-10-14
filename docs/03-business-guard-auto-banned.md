# 👤 Domain Business Guard & Auto-Banned Pengguna

Panduan integrasi keamanan level logika bisnis di Controller (IDOR, Tampering) dan eksekusi Auto-Banned akun secara otomatis.

---

## 1. Konsep Domain Business Guard

Firewall jaringan biasa (WAF) tidak bisa mengetahui apakah Pemohon A berhak membuka Berkas B atau tidak. Hanya **Controller / Policy aplikasi** yang memegang logika otorisasi tersebut.

Ketika terjadi percobaan **IDOR (Insecure Direct Object Reference)** di mana pengguna mencoba mengakses ID permohonan atau dokumen milik orang lain, controller melaporkan pelanggaran ini ke AppGuard menggunakan Facade:

```php
use AppGuard\Facades\SecurityGuard;
```

---

## 2. Implementasi di Controller (Contoh Kasus Simponie)

Berikut contoh pencegahan IDOR pada berkas dan data permohonan:

```php
namespace App\Http\Controllers;

use App\Models\Permohonan;
use AppGuard\Facades\SecurityGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class PermohonanController extends Controller
{
    public function show($id)
    {
        $permohonan = Permohonan::findOrFail($id);

        // Validasi kepemilikan data:
        if ($permohonan->user_id !== Auth::id()) {
            // Laporkan pelanggaran IDOR ke AppGuard (25 poin)
            SecurityGuard::recordViolation(
                Auth::user(),
                'idor',
                25,
                "Percobaan akses detail permohonan #{$id} milik akun lain"
            );

            abort(403, 'Akses tidak diizinkan.');
        }

        return view('permohonan.show', compact('permohonan'));
    }

    public function downloadBerkas($id, $berkasId)
    {
        $permohonan = Permohonan::findOrFail($id);

        if ($permohonan->user_id !== Auth::id()) {
            SecurityGuard::recordViolation(
                Auth::user(),
                'idor',
                25,
                "Percobaan streaming/download berkas #{$berkasId} milik permohonan orang lain"
            );

            abort(403, 'Akses ditolak.');
        }

        // Lanjutkan unduh file...
    }
}
```

---

## 3. Alur Kerja Auto-Banned Pengguna

Ketika akumulasi poin penalti seorang pengguna mencapai ambang batas (default **100 poin**, misal 4x mencoba IDOR dalam window waktu 30 menit):

1. **Mutasi Kolom Database Otomatis (Mendukung Multi-Field):**
   AppGuard mengeksekusi update pada atribut model yang dikonfigurasi di `config/guard.php` (array key-value):
   ```php
   'user_ban' => [
       'model' => env('GUARD_USER_MODEL', 'App\\Models\\User'),
       'attributes' => [
           'c_status' => 1,
           // Bisa menambah field lain, misal: 'is_active' => 0, 'banned_at' => now()
       ],
   ],
   ```
   Saat terjadi pemblokiran, seluruh kolom pada array `attributes` di-update sekaligus di database.
2. **Karantina Cache:**
   Status blokir user dicatat di Cache/Redis (`block:user:{id}`) selama 7 hari.
3. **Penyelamatan Bukti Celah (Dataset ML):**
   Rincian pelanggaran dicatat ke file dataset JSONL `vulnerabilities.jsonl`.
4. **Trigger Laravel Event:**
   Event `AppGuard\Events\UserBanned` ditembakkan sehingga aplikasi induk bisa menjalankan pembersihan tambahan (misalnya menghapus sesi tabel `ActiveUser`).
5. **Notifikasi Darurat Telegram (Tebot):**
   Alert dikirim seketika ke grup Telegram pengawas DPMPTSP/Keamanan.
6. **Force Logout & Response 403:**
   Sesi autentikasi klien langsung dihancurkan (`Auth::logout()`, invalidate session) dan diarahkan kembali ke halaman login dengan pesan:
   > *"Akun Anda telah dinonaktifkan oleh sistem keamanan karena aktivitas yang tidak wajar."*
