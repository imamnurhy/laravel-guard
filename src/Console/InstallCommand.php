<?php

namespace AppGuard\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class InstallCommand extends Command
{
    protected $signature = 'guard:install';
    protected $description = 'Setup and install AppGuard configuration and environment prerequisites';

    public function handle(): int
    {
        $this->info('🛡️  Memasang AppGuard...');

        // 1. Publish config
        $this->call('vendor:publish', [
            '--tag' => 'guard-config',
            '--force' => false,
        ]);

        // 2. Pastikan file dataset tersimpan di storage/app/guard
        $datasetDir = storage_path('app/guard');
        if (!File::exists($datasetDir)) {
            File::makeDirectory($datasetDir, 0755, true);
            File::put($datasetDir . '/.gitignore', "*\n!.gitignore\n");
            $this->info("📁 Direktori penyimpanan dataset dibuat di {$datasetDir}");
        }

        // 3. Rekomendasi pendaftaran middleware & .env
        $this->line('');
        $this->comment('Langkah Integrasi Middleware:');
        $this->line('  Tambahkan \AppGuard\Http\GuardMiddleware::class ke dalam grup "web" / $middleware di app/Http/Kernel.php');
        $this->line('  atau gunakan alias route "guard" pada endpoint tertentu.');
        $this->line('');
        $this->comment('Pastikan variabel berikut terdefinisi di file .env Anda:');
        $this->line('  GUARD_ENABLED=true');
        $this->line('  GUARD_MODE=monitor # Gunakan "monitor" untuk rollout awal, "enforce" untuk aktif penuh');
        $this->line('  GUARD_CACHE_STORE=redis # Disarankan redis untuk performa produksi');
        $this->line('  GUARD_TEBOT_ENABLED=true');
        $this->line('');

        $this->info('✅ AppGuard berhasil dipasang!');
        return self::SUCCESS;
    }
}
