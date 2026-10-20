# 📖 Contoh Kode Integrasi AppGuard (Host Application Boilerplate)

Dokumen ini menyediakan contoh kode siap pakai (*copy-pasteable*) untuk mengintegrasikan AppGuard ke dalam aplikasi host Laravel.

---

## 🔒 1. Mitigasi IDOR pada Berbagai Skenario Controller

### A. Pada Resource Controller (Master-Detail / Dokumen)
```php
namespace App\Http\Controllers;

use App\Models\Permohonan;
use AppGuard\Facades\SecurityGuard;
use Illuminate\Http\Request;

class PermohonanController extends Controller
{
    public function show($id)
    {
        $permohonan = Permohonan::findOrFail($id);

        // Verifikasi kepemilikan data (Anti-IDOR)
        if ($permohonan->user_id !== auth()->id() && !auth()->user()->is_petugas) {
            SecurityGuard::recordViolation(
                user: auth()->user(),
                type: 'idor_permohonan',
                score: 35,
                reason: "Percobaan akses berkas permohonan #{$id} tanpa otorisasi sah"
            );

            abort(403, 'Akses dilarang.');
        }

        return view('permohonan.show', compact('permohonan'));
    }

    public function destroy($id)
    {
        $permohonan = Permohonan::findOrFail($id);

        if ($permohonan->user_id !== auth()->id()) {
            // Pelanggaran penghapusan data orang lain diberi bobot lebih tinggi (50 poin)
            SecurityGuard::recordViolation(
                user: auth()->user(),
                type: 'tampering_delete',
                score: 50,
                reason: "Percobaan menghapus data permohonan #{$id} milik user lain"
            );

            abort(403);
        }

        $permohonan->delete();
        return redirect()->route('permohonan.index')->with('success', 'Data dihapus.');
    }
}
```

---

## 👤 2. Implementasi Kustom User Ban Handler

Gunakan pola ini jika aplikasi host Anda menggunakan kolom status non-standar (misal: `status = 'suspended'` atau `is_banned = true`):

```php
namespace App\Security;

use AppGuard\Contracts\UserBanHandler;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Session;

class CustomUserBanHandler implements UserBanHandler
{
    public function ban(Authenticatable $user, int $score, string $reason): void
    {
        // 1. Mutasi status basis data
        DB::table('users')
            ->where('id', $user->getAuthIdentifier())
            ->update([
                'status'        => 'suspended',
                'banned_at'     => now(),
                'banned_reason' => $reason,
                'updated_at'    => now(),
            ]);

        // 2. Putus seluruh sesi aktif pengguna di database (jika session driver = database)
        if (config('session.driver') === 'database') {
            DB::table('sessions')
                ->where('user_id', $user->getAuthIdentifier())
                ->delete();
        }

        // 3. Bersihkan sesi lokal request saat ini
        Session::flush();
        Session::regenerate(true);
    }

    public function isBanned(Authenticatable $user): bool
    {
        return $user->status === 'suspended';
    }
}
```

Daftarkan di `config/guard.php`:
```php
'user_ban' => [
    'enabled' => true,
    'handler' => App\Security\CustomUserBanHandler::class,
],
```

---

## 📢 3. Event Listener untuk `UserBanned` (Audit Trail)

Buat listener untuk mencatat audit internal atau mengirim email peringatan:

```php
namespace App\Listeners;

use AppGuard\Events\UserBanned;
use Illuminate\Support\Facades\Log;

class LogUserBannedEvent
{
    public function handle(UserBanned $event): void
    {
        Log::channel('security')->critical("User Terbanned Otomatis oleh AppGuard", [
            'user_id' => $event->user->getAuthIdentifier(),
            'score'   => $event->score,
            'reason'  => $event->reason,
            'ip'      => request()->ip(),
            'time'    => now()->toIso8601String(),
        ]);
    }
}
```

Daftarkan di `app/Providers/EventServiceProvider.php`:
```php
protected $listen = [
    \AppGuard\Events\UserBanned::class => [
        \App\Listeners\LogUserBannedEvent::class,
    ],
];
```
