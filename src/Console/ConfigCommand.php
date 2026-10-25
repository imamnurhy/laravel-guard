<?php

namespace AppGuard\Console;

use Illuminate\Console\Command;

/**
 * Command untuk mengaudit, membandingkan (diff), menampilkan snippet,
 * dan menyinkronkan konfigurasi config/guard.php dengan default package.
 */
class ConfigCommand extends Command
{
    protected $signature = 'guard:config
        {--diff : Tampilkan perbandingan detail antara konfigurasi package default vs host app}
        {--sync : Sinkronkan key baru/absen dari package ke dalam config/guard.php host secara aman}
        {--snippet= : Tampilkan potongan kode konfigurasi siap salin untuk key tertentu}
        {--key= : Filter perbandingan, snippet, atau sinkronisasi hanya pada key tertentu}
        {--force : Lewati konfirmasi saat melakukan sinkronisasi}
        {--json : Tampilkan keluaran dalam format JSON}';

    protected $description = 'Audit, bandingkan (diff), dan sinkronkan config/guard.php dengan default package secara aman';

    public function handle(): int
    {
        $packageConfigPath = __DIR__ . '/../../config/guard.php';
        $hostConfigPath = function_exists('config_path') ? config_path('guard.php') : '';

        if (! file_exists($packageConfigPath)) {
            $this->error("Berkas konfigurasi default package tidak ditemukan di: {$packageConfigPath}");

            return self::FAILURE;
        }

        $packageConfig = require $packageConfigPath;
        $hostExists = ! empty($hostConfigPath) && file_exists($hostConfigPath);
        $hostRaw = $hostExists ? (require $hostConfigPath) : [];
        $packageContent = file_get_contents($packageConfigPath);

        // Ekstraksi blok kode sumber asli (lengkap dengan komentar & env)
        $packageBlocks = $this->extractPackageBlocks($packageContent);
        $detectorBlocks = $this->extractDetectorBlocks($packageContent);

        // 1. Mode Snippet: Menampilkan potongan kode siap salin
        $snippetKey = $this->option('snippet') ?: ($this->option('key') && ! $this->option('diff') && ! $this->option('sync') ? $this->option('key') : null);
        if ($snippetKey && ! $this->option('diff') && ! $this->option('sync')) {
            return $this->handleSnippet($snippetKey, $packageBlocks, $detectorBlocks);
        }

        // 2. Mode Sync: Menyinkronkan key baru/absen ke dalam config/guard.php
        if ($this->option('sync')) {
            return $this->handleSync($hostConfigPath, $packageConfig, $hostRaw, $packageBlocks, $detectorBlocks);
        }

        // 3. Analisis Komparasi Kunci
        $analysis = $this->analyzeConfig($packageConfig, $hostRaw);

        // Filter berdasarkan --key jika diminta
        if ($filterKey = $this->option('key')) {
            $analysis = array_filter($analysis, fn ($item, $k) => str_starts_with($k, $filterKey), ARRAY_FILTER_USE_BOTH);
            if (empty($analysis)) {
                $this->warn("Tidak ditemukan konfigurasi yang cocok dengan kunci: [{$filterKey}]");

                return self::SUCCESS;
            }
        }

        // 4. Output JSON
        if ($this->option('json')) {
            $this->line((string) json_encode([
                'host_config_path' => $hostConfigPath,
                'host_exists'      => $hostExists,
                'summary'          => [
                    'total_package_keys' => count($packageConfig),
                    'custom_host_keys'   => count(array_filter($analysis, fn ($i) => $i['status'] === 'custom')),
                    'inherited_keys'     => count(array_filter($analysis, fn ($i) => $i['status'] === 'inherited')),
                ],
                'items' => $analysis,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        // 5. Mode Diff atau Overview
        if ($this->option('diff')) {
            return $this->renderDiffTable($analysis);
        }

        return $this->renderOverviewTable($hostConfigPath, $hostExists, $analysis, $packageBlocks);
    }

    /**
     * Tampilkan snippet kode konfigurasi package yang rapi untuk disalin.
     */
    protected function handleSnippet(string $key, array $packageBlocks, array $detectorBlocks): int
    {
        $target = trim($key);
        $code = null;

        if (str_starts_with($target, 'detectors.')) {
            $detKey = substr($target, 10);
            $code = $detectorBlocks[$detKey] ?? null;
        } elseif (isset($packageBlocks[$target])) {
            $code = $packageBlocks[$target];
        } elseif (isset($detectorBlocks[$target])) {
            $code = $detectorBlocks[$target];
        }

        if (! $code) {
            $this->error("Snippet untuk konfigurasi [{$target}] tidak ditemukan di default package.");
            $this->line("Kunci yang tersedia di top-level: " . implode(', ', array_keys($packageBlocks)));
            $this->line("Detektor yang tersedia: " . implode(', ', array_keys($detectorBlocks)));

            return self::FAILURE;
        }

        $this->newLine();
        $this->line("  📋 <options=bold>AppGuard Config Snippet</> — <fg=cyan>{$target}</>");
        $this->line("  <fg=gray>Salin potongan kode berikut ke dalam config/guard.php Anda:</>");
        $this->newLine();
        $this->line($code . (str_ends_with(trim($code), ',') ? '' : ','));
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Sinkronkan key baru/absen ke dalam berkas fisik config/guard.php secara aman.
     */
    protected function handleSync(string $hostConfigPath, array $packageConfig, array $hostRaw, array $packageBlocks, array $detectorBlocks): int
    {
        if (empty($hostConfigPath) || ! file_exists($hostConfigPath)) {
            $this->error("Berkas konfigurasi host [config/guard.php] tidak ditemukan.");
            $this->line("Gunakan 'php artisan vendor:publish --tag=guard-config' terlebih dahulu.");

            return self::FAILURE;
        }

        $filterKey = $this->option('key');
        $candidates = [];

        if ($filterKey) {
            if (isset($packageBlocks[$filterKey])) {
                if (array_key_exists($filterKey, $hostRaw)) {
                    $this->warn("Kunci [{$filterKey}] sudah ada di dalam config/guard.php host.");
                    if (! $this->option('force') && ! $this->confirm("Apakah Anda ingin tetap menyisipkannya lagi?")) {
                        return self::SUCCESS;
                    }
                }
                $candidates[$filterKey] = $packageBlocks[$filterKey];
            } elseif (str_starts_with($filterKey, 'detectors.') && isset($detectorBlocks[substr($filterKey, 10)])) {
                $subKey = substr($filterKey, 10);
                $candidates[$filterKey] = $detectorBlocks[$subKey];
            } else {
                $this->error("Kunci [{$filterKey}] tidak ditemukan dalam default package.");

                return self::FAILURE;
            }
        } else {
            // Deteksi kunci top-level yang belum ada di host app
            foreach ($packageBlocks as $key => $code) {
                if (! array_key_exists($key, $hostRaw)) {
                    $candidates[$key] = $code;
                }
            }
        }

        if (empty($candidates)) {
            $this->info("✅ Berkas config/guard.php Anda sudah lengkap. Tidak ada opsi yang perlu disinkronkan.");
            $this->line("   (Seluruh pengaturan default package lainnya diwarisi secara otomatis di runtime).");

            return self::SUCCESS;
        }

        $this->newLine();
        $this->line("  🔄 <options=bold>AppGuard Safe Config Sync</>");
        $this->newLine();
        $this->line("Ditemukan <fg=yellow>" . count($candidates) . "</> konfigurasi dari package yang belum tertulis di <fg=cyan>config/guard.php</>:");
        foreach (array_keys($candidates) as $k) {
            $this->line("  • <fg=cyan>{$k}</>");
        }
        $this->newLine();

        if (! $this->option('force') && ! $this->confirm("Apakah Anda ingin menyisipkan opsi tersebut ke dalam config/guard.php sekarang? (Aman: Backup otomatis dibuat)", true)) {
            $this->comment("Sinkronisasi dibatalkan.");

            return self::SUCCESS;
        }

        // 1. Buat backup otomatis
        $hostContent = file_get_contents($hostConfigPath);
        $backupPath = $hostConfigPath . '.bak_' . date('Ymd_His');
        if (file_put_contents($backupPath, $hostContent) === false) {
            $this->error("Gagal membuat berkas cadangan (backup) di {$backupPath}. Operasi dibatalkan.");

            return self::FAILURE;
        }
        $this->line("📁 Backup aman dibuat: <fg=gray>{$backupPath}</>");

        // 2. Cari posisi kurung penutup array return [ ... ];
        $lastBracketPos = strrpos($hostContent, '];');
        if ($lastBracketPos === false) {
            $lastBracketPos = strrpos($hostContent, ');');
        }

        if ($lastBracketPos === false) {
            $this->error("Gagal mendeteksi sintaks penutup array '];' pada config/guard.php.");
            unlink($backupPath);

            return self::FAILURE;
        }

        // 3. Format dan sisipkan blok baru
        $blocksToInsert = "\n";
        foreach ($candidates as $key => $code) {
            $indented = "    " . str_replace("\n", "\n    ", trim($code));
            if (! str_ends_with(trim($indented), ',')) {
                $indented .= ',';
            }
            $blocksToInsert .= "\n" . $indented . "\n";
        }

        $newHostContent = substr($hostContent, 0, $lastBracketPos) . $blocksToInsert . substr($hostContent, $lastBracketPos);

        // Tulis ke file host
        file_put_contents($hostConfigPath, $newHostContent);

        // 4. Verifikasi Integritas Sintaks PHP (php -l)
        $lintResult = $this->lintPhpFile($hostConfigPath);
        if ($lintResult !== true) {
            // Pulihkan backup seketika
            file_put_contents($hostConfigPath, $hostContent);
            $this->error("❌ Gagal menyinkronkan: sintaks berkas tidak valid ({$lintResult}).");
            $this->warn("Berkas config/guard.php asli telah dipulihkan secara otomatis.");

            return self::FAILURE;
        }

        $this->info("✅ Berhasil menyinkronkan " . count($candidates) . " konfigurasi ke config/guard.php!");
        $this->line("   Pengaturan kustom lama Anda tetap 100% utuh tanpa perubahan.");
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Analisis perbandingan antara package default dengan host config.
     */
    protected function analyzeConfig(array $packageConfig, array $hostRaw): array
    {
        $analysis = [];

        foreach ($packageConfig as $key => $pkgVal) {
            $isCustom = array_key_exists($key, $hostRaw);
            $hostVal = $isCustom ? $hostRaw[$key] : null;

            if ($isCustom && is_array($pkgVal) && is_array($hostVal) && ! array_is_list($pkgVal) && ! array_is_list($hostVal)) {
                // Analisis sub-kunci untuk asosiatif map (e.g. detectors, profiles, user_ban)
                $analysis[$key] = [
                    'key'           => $key,
                    'status'        => 'custom',
                    'host_val'      => '(Array Kustom)',
                    'pkg_val'       => '(Array Default)',
                    'desc'          => 'Bagian array telah disesuaikan sebagian oleh host app',
                    'sub_keys_info' => count($hostVal) . ' kustom / ' . count($pkgVal) . ' total default',
                ];

                foreach ($pkgVal as $subKey => $pkgSubVal) {
                    $subPath = "{$key}.{$subKey}";
                    $subIsCustom = array_key_exists($subKey, $hostVal);
                    $analysis[$subPath] = [
                        'key'      => $subPath,
                        'status'   => $subIsCustom ? 'custom' : 'inherited',
                        'host_val' => $subIsCustom ? $this->formatVal($hostVal[$subKey]) : '(Inherited)',
                        'pkg_val'  => $this->formatVal($pkgSubVal),
                        'desc'     => $subIsCustom ? 'Didefinisikan khusus di host' : 'Diwarisi otomatis dari default package',
                    ];
                }
            } else {
                $analysis[$key] = [
                    'key'      => $key,
                    'status'   => $isCustom ? 'custom' : 'inherited',
                    'host_val' => $isCustom ? $this->formatVal($hostVal) : '(Inherited)',
                    'pkg_val'  => $this->formatVal($pkgVal),
                    'desc'     => $isCustom ? 'Didefinisikan khusus di host' : 'Diwarisi otomatis dari default package',
                ];
            }
        }

        // Periksa apakah host mendefinisikan kunci kustom yang tidak ada di package default
        foreach ($hostRaw as $key => $hostVal) {
            if (! array_key_exists($key, $packageConfig)) {
                $analysis[$key] = [
                    'key'      => $key,
                    'status'   => 'host_only',
                    'host_val' => $this->formatVal($hostVal),
                    'pkg_val'  => '(None)',
                    'desc'     => 'Kunci kustom tambahan murni milik host app',
                ];
            }
        }

        return $analysis;
    }

    /**
     * Tampilkan tabel ringkasan umum (Overview).
     */
    protected function renderOverviewTable(string $hostPath, bool $hostExists, array $analysis, array $packageBlocks): int
    {
        $this->newLine();
        $this->line('  🛡️  <options=bold>AppGuard Configuration Status & Sync</>');
        $this->newLine();

        $customCount = count(array_filter($analysis, fn ($i) => $i['status'] === 'custom' && ! str_contains($i['key'], '.')));
        $inheritedCount = count(array_filter($analysis, fn ($i) => $i['status'] === 'inherited' && ! str_contains($i['key'], '.')));

        $this->table([], [
            ['Berkas Host App', $hostExists ? "<fg=green>{$hostPath}</>" : "<fg=red>Belum dibuat</>"],
            ['Kunci Disesuaikan (Host Override)', "<fg=green;options=bold>{$customCount}</> bagian kustom"],
            ['Kunci Diwarisi (Package Default)', "<fg=cyan;options=bold>{$inheritedCount}</> bagian otomatis via runtime merge"],
            ['Total Bagian Package', count($packageBlocks) . ' bagian'],
        ]);

        $this->newLine();
        $this->line('  <options=bold>Status Bagian Konfigurasi (Top-Level Sections):</>');

        $rows = [];
        foreach ($packageBlocks as $k => $c) {
            $item = $analysis[$k] ?? null;
            $statusStr = '<fg=gray>Unknown</>';
            $detail = '-';

            if ($item) {
                if ($item['status'] === 'custom') {
                    $statusStr = '<fg=green;options=bold>✓ Kustom (Host)</>';
                    $detail = $item['sub_keys_info'] ?? $item['host_val'];
                } elseif ($item['status'] === 'inherited') {
                    $statusStr = '<fg=cyan>• Diwarisi (Default)</>';
                    $detail = 'Otomatis aktif dari package';
                }
            }

            $rows[] = [$k, $statusStr, $detail];
        }

        $this->table(['Bagian Konfigurasi (Key)', 'Status di Host App', 'Keterangan'], $rows);

        $this->newLine();
        $this->comment('Perintah yang dapat digunakan:');
        $this->line('  • <fg=yellow>php artisan guard:config --diff</>             : Lihat perbandingan detail nilai');
        $this->line('  • <fg=yellow>php artisan guard:config --snippet=<key></>      : Lihat potongan kode siap salin untuk key tertentu');
        $this->line('  • <fg=yellow>php artisan guard:config --sync --key=<key></>   : Sisipkan key secara aman ke config/guard.php');
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Tampilkan tabel perbandingan detail (Diff).
     */
    protected function renderDiffTable(array $analysis): int
    {
        $this->newLine();
        $this->line('  🔍 <options=bold>AppGuard Configuration Diff (Host vs Package Default)</>');
        $this->newLine();

        $rows = [];
        foreach ($analysis as $item) {
            $statusBadge = match ($item['status']) {
                'custom'    => '<fg=green;options=bold>✓ Kustom</>',
                'inherited' => '<fg=cyan>• Diwarisi</>',
                'host_only' => '<fg=yellow>+ Host Only</>',
                default     => '<fg=gray>?</>',
            };

            $rows[] = [
                $item['key'],
                $statusBadge,
                $item['host_val'],
                $item['pkg_val'],
            ];
        }

        $this->table(['Kunci (Config Key)', 'Status', 'Nilai di Host App', 'Nilai Default Package'], $rows);
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Ekstraksi blok konfigurasi top-level dari berkas PHP sumber package.
     */
    protected function extractPackageBlocks(string $content): array
    {
        $tokens = token_get_all($content);
        $depth = 0;
        $blocks = [];
        $pendingComments = '';
        $currentKey = null;
        $currentCode = '';

        foreach ($tokens as $idx => $tok) {
            $text = is_array($tok) ? $tok[1] : $tok;
            $id = is_array($tok) ? $tok[0] : null;

            if ($depth === 1 && ($id === T_COMMENT || $id === T_DOC_COMMENT || $id === T_WHITESPACE)) {
                if ($currentKey === null) {
                    $pendingComments .= $text;
                    continue;
                }
            }

            if ($depth === 1 && $id === T_CONSTANT_ENCAPSED_STRING) {
                $j = $idx + 1;
                while (isset($tokens[$j]) && is_array($tokens[$j]) && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT])) {
                    $j++;
                }
                if (isset($tokens[$j]) && is_array($tokens[$j]) && $tokens[$j][0] === T_DOUBLE_ARROW) {
                    $currentKey = trim($text, "\x22\x27");
                    $currentCode = ltrim($pendingComments, "\r\n") . $text;
                    $pendingComments = '';
                    continue;
                }
            }

            if ($currentKey !== null) {
                $currentCode .= $text;
                if ($depth === 1 && $text === ',') {
                    $blocks[$currentKey] = trim($currentCode);
                    $currentKey = null;
                    $currentCode = '';
                }
            }

            if ($tok === '[' || $id === T_ARRAY) {
                $depth++;
            } elseif ($tok === ']') {
                $depth--;
            }
        }

        return $blocks;
    }

    /**
     * Ekstraksi blok sub-detektor dari berkas PHP sumber package.
     */
    protected function extractDetectorBlocks(string $content): array
    {
        $tokens = token_get_all($content);
        $depth = 0;
        $inDetectors = false;
        $detectorBlocks = [];
        $pendingComments = '';
        $currentDetector = null;
        $currentCode = '';

        foreach ($tokens as $idx => $tok) {
            $text = is_array($tok) ? $tok[1] : $tok;
            $id = is_array($tok) ? $tok[0] : null;

            if ($depth === 1 && $id === T_CONSTANT_ENCAPSED_STRING && trim($text, "\x22\x27") === 'detectors') {
                $inDetectors = true;
            }

            if ($inDetectors && $depth === 2 && ($id === T_COMMENT || $id === T_DOC_COMMENT || $id === T_WHITESPACE)) {
                if ($currentDetector === null) {
                    $pendingComments .= $text;
                    continue;
                }
            }

            if ($inDetectors && $depth === 2 && $id === T_CONSTANT_ENCAPSED_STRING) {
                $j = $idx + 1;
                while (isset($tokens[$j]) && is_array($tokens[$j]) && in_array($tokens[$j][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT])) {
                    $j++;
                }
                if (isset($tokens[$j]) && is_array($tokens[$j]) && $tokens[$j][0] === T_DOUBLE_ARROW) {
                    $currentDetector = trim($text, "\x22\x27");
                    $currentCode = ltrim($pendingComments, "\r\n") . $text;
                    $pendingComments = '';
                    continue;
                }
            }

            if ($currentDetector !== null) {
                $currentCode .= $text;
                if ($depth === 2 && $text === ',') {
                    $detectorBlocks[$currentDetector] = trim($currentCode);
                    $currentDetector = null;
                    $currentCode = '';
                }
            }

            if ($tok === '[' || $id === T_ARRAY) {
                $depth++;
            } elseif ($tok === ']') {
                $depth--;
                if ($depth === 1) {
                    $inDetectors = false;
                }
            }
        }

        return $detectorBlocks;
    }

    /**
     * Format nilai konfigurasi agar ringkas dan jelas di layar tabel.
     */
    protected function formatVal(mixed $val): string
    {
        if ($val === null) return 'null';
        if (is_bool($val)) return $val ? 'true' : 'false';
        if (is_numeric($val)) return (string) $val;
        if (is_string($val)) return "'{$val}'";
        if (is_array($val)) {
            if (empty($val)) return '[]';
            if (array_is_list($val)) {
                $count = count($val);
                $first = array_slice($val, 0, 3);
                $preview = implode(', ', array_map(fn ($v) => is_scalar($v) ? (string) $v : '...', $first));
                return "[{$preview}" . ($count > 3 ? ", ... ({$count} item)" : "") . "]";
            }
            return "{ " . implode(', ', array_slice(array_keys($val), 0, 3)) . (count($val) > 3 ? ', ...' : '') . " }";
        }

        return is_object($val) ? get_class($val) : (string) $val;
    }

    /**
     * Lint file PHP untuk memverifikasi sintaks.
     */
    protected function lintPhpFile(string $filePath): bool|string
    {
        $escaped = escapeshellarg($filePath);
        $output = [];
        $exitCode = 0;
        exec("php -l {$escaped} 2>&1", $output, $exitCode);

        if ($exitCode === 0) {
            return true;
        }

        return implode("\n", $output);
    }
}
