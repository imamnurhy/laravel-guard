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
    | Mendukung nama variabel pendek (GUARD_URL, GUARD_KEY, GUARD_SECRET, GUARD_PUBKEY)
    | serta nama legacy untuk backward-compatibility.
    */
    'control_plane' => [
        'url' => env('GUARD_URL', env('GUARD_CONTROL_PLANE_URL')),
        'app_key' => env('GUARD_KEY', env('GUARD_APP_KEY')),
        'app_secret' => env('GUARD_SECRET', env('GUARD_APP_SECRET')),
        'public_key' => env('GUARD_PUBKEY', env('GUARD_PUBLIC_KEY')),
        'timeout' => (int) env('GUARD_TIMEOUT', env('GUARD_SYNC_TIMEOUT', 3)),
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
        'throttle' => (int) env('GUARD_THROTTLE', env('GUARD_THROTTLE_THRESHOLD', 50)),
        'block' => (int) env('GUARD_BLOCK', env('GUARD_BLOCK_THRESHOLD', 100)),
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
        'enabled' => env('GUARD_BAN_ENABLED', env('GUARD_USER_BAN_ENABLED', true)),
        'threshold' => (int) env('GUARD_BAN_THRESHOLD', env('GUARD_USER_BAN_THRESHOLD', 100)),
        'duration' => 604800, // Durasi banned di cache (7 hari)
        
        // Konfigurasi Model Eloquent aplikasi
        'model' => env('GUARD_USER_MODEL', 'App\\Models\\User'),

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
    | Notifikasi Darurat (Tebot / Telegram)
    |--------------------------------------------------------------------------
    | Otomatis mengirim peringatan ke Telegram saat terjadi Auto-Banned / serangan kritis.
    | Failsafe: Jika package explorin/tebot tidak ada, otomatis fallback ke Log file.
    */
    'tebot' => [
        'enabled' => env('GUARD_TEBOT_ENABLED', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Incident / Vulnerability Exposure Storage (Dataset Forensik)
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
                '.env*', '.git/*', 'wp-admin*', 'wp-login.php', 'xmlrpc.php',
                'phpmyadmin*', 'vendor/phpunit/*', 'cgi-bin/*', 'config.json', 'backup*.sql',
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
            'safe_fields' => [
                'alamat', 'lokasi_izin_alamat', 'alasan', 'alasan_perbaikan',
                'keterangan', 'catatan', 'nama', 'realname', 'n_perusahaan', 'alamat_perusahaan', 'judul',
            ],
        ],

        'parameter_tampering' => [
            'enabled' => true,
            'score' => 35,
            'forbidden_fields' => [
                'is_admin', 'role', 'role_id', 'status_id', 'is_superuser',
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
            'safe_fields' => [
                'alamat', 'lokasi_izin_alamat', 'alasan', 'alasan_perbaikan',
                'keterangan', 'catatan', 'nama', 'realname', 'n_perusahaan', 'alamat_perusahaan', 'judul',
            ],
        ],
    ],

    /* Detector buatan sendiri: class yang implement AppGuard\Core\Contracts\Detector. */
    'custom_detectors' => [],
];
