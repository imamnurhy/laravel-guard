<?php

return [

    /* Matikan total tanpa uninstall: GUARD_ENABLED=false */
    'enabled' => env('GUARD_ENABLED', true),

    /*
     | monitor = hanya mencatat log apa yang AKAN diblokir (aman untuk rollout awal)
     | enforce = benar-benar menolak request (403/429) dan auto-banned
     */
    'mode' => env('GUARD_MODE', 'monitor'),

    /* Jika guard error (mis. Redis mati): true = loloskan request, false = tolak 503 */
    'fail_open' => true,

    /* Cache store untuk counter. null = default store. Disarankan redis. */
    'store' => env('GUARD_CACHE_STORE'),

    /* Log channel. null = default channel. */
    'log_channel' => env('GUARD_LOG_CHANNEL'),

    /*
    |--------------------------------------------------------------------------
    | Centralized WAF Control Plane Hub Integration
    |--------------------------------------------------------------------------
    | Konfigurasi ringkas koneksi tenant ke Centralized Control Plane.
    | Menggunakan variabel standar ringkas: GUARD_URL, GUARD_KEY, GUARD_SECRET, GUARD_PUBKEY.
    */
    'control_plane' => [
        'url' => env('GUARD_URL'),
        'app_key' => env('GUARD_KEY'),
        'app_secret' => env('GUARD_SECRET'),
        'public_key' => env('GUARD_PUBKEY'),
        'timeout' => (int) env('GUARD_TIMEOUT', 3),
    ],


    /*
    |--------------------------------------------------------------------------
    | Allowlist Pengecualian IP (Bypass Guard)
    |--------------------------------------------------------------------------
    | IP address atau CIDR subnet yang tidak pernah diperiksa (bypass total WAF & scoring).
    | Contoh: ['127.0.0.1', '192.168.1.0/24', '10.0.0.0/8']
    */
    'allowlist' => [
        // '127.0.0.1',
    ],

    /* Skor >= throttle -> dibatasi lajunya, skor >= block -> ditolak. */
    'thresholds' => [
        'throttle' => (int) env('GUARD_THROTTLE', 50),
        'block' => (int) env('GUARD_BLOCK', 100),
    ],

    /* Ambang berbeda per kelompok path (wildcard fnmatch). Yang cocok pertama dipakai. */
    'profiles' => [
        'strict' => [
            'throttle' => 30,
            'block' => 70,
            'paths' => ['login', 'register', 'password/*', 'api/login', 'api/auth/*'],
        ],
    ],

    'reputation_ttl' => (int) env('GUARD_REPUTATION_TTL', 1800), // detik: berapa lama skor pelanggaran diingat
    'throttle_per_minute' => 10,  // laju yang masih diizinkan saat status throttle

    /* Nama input yang dianggap identitas login (untuk brute force per akun). */
    'identifier_keys' => ['email', 'username', 'login'],

    /*
    |--------------------------------------------------------------------------
    | Auto-Banned Akun Pengguna (Database & Session Level)
    |--------------------------------------------------------------------------
    | Mengubah status akun di database ketika mencapai ambang batas pelanggaran,
    | serta memutuskan sesi secara paksa (Force Logout).
    */
    'user_ban' => [
        'enabled' => env('GUARD_BAN_ENABLED', true),
        'threshold' => (int) env('GUARD_BAN_THRESHOLD', 100),
        'duration' => 604800, // Durasi banned di cache (7 hari)

        // Konfigurasi Model Eloquent aplikasi pengguna (ubah langsung di sini jika memakai custom model)
        'model' => App\Models\User::class,

        /*
         | Kolom database pengguna yang diubah saat akun di-banned.
         | Format: ['nama_kolom' => nilai_banned, ...]
         | Contoh: ['status' => 'banned'] atau ['is_active' => false] atau ['c_status' => 1]
         */
        'attributes' => [
            // 'is_active' => false,
        ],

        'redirect_route' => 'login',
    ],

    /*
    |--------------------------------------------------------------------------
    | Incident / Vulnerability Exposure Storage (Dataset Forensik & Telemetri)
    |--------------------------------------------------------------------------
    | Menyimpan payload, path, respon, dan celah yang berhasil terekspose
    | ke format JSONL terstruktur sebagai bahan audit forensik dan analisis keamanan.
    */
    'vulnerability' => [
        'dataset_path' => storage_path('app/guard/vulnerabilities.jsonl'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Bobot Skor Pelanggaran Khusus Aplikasi (Rules / Violations)
    |--------------------------------------------------------------------------
    */
    'rules' => [
        'idor' => [
            'points' => 25,
            'description' => 'Percobaan akses tidak sah pada data/berkas milik akun lain (IDOR)',
        ],
        'path_traversal' => [
            'points' => 50,
            'description' => 'Percobaan Directory/Path Traversal pada penanganan berkas',
        ],
        'malicious_upload' => [
            'points' => 50,
            'description' => 'Percobaan unggah berkas mencurigakan atau berbahaya',
        ],
        'sqli' => [
            'points' => 100, // Langsung auto-banned
            'description' => 'Percobaan eksploitasi SQL Injection terdeteksi',
        ],
        'xss' => [
            'points' => 50,
            'description' => 'Percobaan injeksi skrip berbahaya (XSS)',
        ],
        'parameter_tampering' => [
            'points' => 35,
            'description' => 'Manipulasi parameter atau injeksi field sensitif (Parameter Tampering)',
        ],
        'captcha_abuse' => [
            'points' => 35,
            'description' => 'Percobaan manipulasi atau replay token CAPTCHA secara tidak sah',
        ],
        'scanner_fuzzing' => [
            'points' => 50,
            'description' => 'Aktivitas pemindaian celah / automated scanner fuzzing terdeteksi',
        ],
        'high_entropy' => [
            'points' => 35,
            'description' => 'Payload anomali dengan pola keacakan berlebih / obfuscation (Shannon Entropy)',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Detektor Bawaan (Built-in Detectors)
    |--------------------------------------------------------------------------
    */
    'detectors' => [

        'honeypot' => [
            'enabled' => true,
            'score' => 100,
            'paths' => [
                '.env*',
                '.git/*',
                'wp-admin*',
                'wp-login.php',
                'xmlrpc.php',
                'phpmyadmin*',
                'vendor/phpunit/*',
                'cgi-bin/*',
                'config.json',
                'backup*.sql',
            ],
            'fields' => [],
        ],

        'brute_force' => [
            'enabled' => true,
            'paths' => ['login', 'api/login', 'api/auth/*', 'password/email'],
            'window' => 900,
            'max_per_ip' => 20,
            'max_per_identifier' => 8,
            'max_per_pair' => 5,
            'score_ip' => 100,
            'score_identifier' => 60,
            'score_pair' => 100,
        ],

        'denied_access' => [
            'enabled' => true,
            'statuses' => [403, 404],
            'window' => 60,
            'threshold' => 15,
            'score' => 40,
            'ignore_paths' => ['favicon.ico', 'robots.txt', '*.map', 'apple-touch-icon*'],
        ],

        'path_traversal' => [
            'enabled' => true,
            'score' => 50,
        ],

        'malicious_payload' => [
            'enabled' => true,
            'sqli_score' => 100,
            'xss_score' => 50,
            /*
             | Kolom formulir (field inputs) yang dikecualikan dari scanning payload SQLi/XSS.
             | Kolom seperti editor WYSIWYG, textarea artikel, atau field alamat bebas dapat
             | didaftarkan di sini agar tidak memicu false positive.
             | Contoh: ['content', 'deskripsi', 'alamat', 'body_html']
             */
            'safe_fields' => [
                // 'content', 'deskripsi',
            ],
        ],

        'parameter_tampering' => [
            'enabled' => true,
            'score' => 35,
            'forbidden_fields' => [
                'is_admin',
                'role',
                'role_id',
                'status_id',
                'is_superuser',
            ],
        ],

        'anomaly' => [
            'enabled' => true,
            'entropy_threshold' => 4.5,
            'entropy_min_length' => 120,
            'entropy_score' => 35,
            'fuzzing_window' => 30,
            'fuzzing_threshold' => 15,
            'fuzzing_score' => 50,
            /*
             | Kolom formulir yang dikecualikan dari kalkulasi Shannon Entropy & scanner fuzzing.
             | Field teks panjang bebas (komentar, alasan, artikel) dapat didaftarkan di sini.
             | Contoh: ['catatan', 'keterangan', 'alasan']
             */
            'safe_fields' => [
                // 'catatan', 'keterangan',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Detektor Kustom (Custom Detectors)
    |--------------------------------------------------------------------------
    | Daftarkan kelas detektor buatan sendiri yang mengimplementasikan interface:
    | `AppGuard\Core\Contracts\Detector`
    |
    | Setiap detektor kustom memiliki 2 fase inspeksi:
    | 1. `inspect(RequestContext $ctx): array` (Fase PRE - sebelum controller dieksekusi)
    | 2. `observe(RequestContext $ctx, int $status): array` (Fase POST - setelah response dibuat)
    |
    | Contoh Implementasi Sederhana:
    | -------------------------------------------------------------------------
    | namespace App\Security\Detectors;
    |
    | use AppGuard\Core\Contracts\Detector;
    | use AppGuard\Core\RequestContext;
    | use AppGuard\Core\Signal;
    |
    | class BlockDisallowedUserAgentDetector implements Detector
    | {
    |     public function name(): string
    |     {
    |         return 'disallowed_user_agent';
    |     }
    |
    |     public function inspect(RequestContext $ctx): array
    |     {
    |         $ua = strtolower($ctx->userAgent ?? '');
    |         if (str_contains($ua, 'sqlmap') || str_contains($ua, 'nikto')) {
    |             return [
    |                 new Signal(
    |                     detector: $this->name(),
    |                     score: 100, // Langsung capai threshold blokir
    |                     reason: 'Automated vulnerability scanner UA terdeteksi: ' . $ua,
    |                     metadata: ['user_agent' => $ua]
    |                 ),
    |             ];
    |         }
    |         return [];
    |     }
    |
    |     public function observe(RequestContext $ctx, int $status): array
    |     {
    |         return []; // Tidak melakukan inspeksi di fase post-response
    |     }
    | }
    | -------------------------------------------------------------------------
    | Daftarkan class di bawah:
    | 'custom_detectors' => [
    |     \App\Security\Detectors\BlockDisallowedUserAgentDetector::class,
    | ],
    */
    'custom_detectors' => [
        // \App\Security\Detectors\BlockDisallowedUserAgentDetector::class,
    ],
];
