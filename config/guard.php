<?php

return [

    /*
    |--------------------------------------------------------------------------
    | 1. Operasional & Mode Sistem (Core & Operational Mode)
    |--------------------------------------------------------------------------
    | Pengaturan aktivasi dan perilaku dasar keamanan sistem AppGuard.
    */

    // Status proteksi: false untuk mematikan seluruh filter Guard tanpa uninstall package
    'enabled' => env('GUARD_ENABLED', true),

    // Mode kerja sistem:
    // - 'monitor' : Hanya mencatat log anomali dan serangan (aman untuk masa pengenalan/testing)
    // - 'enforce' : Bertindak tegas memblokir (403/429), force logout, dan auto-ban user
    'mode' => env('GUARD_MODE', 'monitor'),

    // Perilaku saat terjadi kegagalan sistem internal (misal: koneksi Redis/Cache down):
    // - true  : (Fail-Open) Izinkan request lolos demi menjaga ketersediaan layanan publik
    // - false : (Fail-Closed) Tolak request dengan HTTP 503 Service Unavailable demi keamanan
    'fail_open' => env('GUARD_FAIL_OPEN', true),

    // Driver cache untuk penyimpanan skor reputasi (null = mengikuti cache default Laravel, disarankan 'redis')
    'store' => env('GUARD_CACHE_STORE'),

    // Prefix key di cache/Redis serta opsi namespace otomatis per tenant (app_key)
    'key_prefix' => env('GUARD_KEY_PREFIX', 'guard:'),
    'prefix_by_tenant' => env('GUARD_PREFIX_BY_TENANT', false),

    // Channel log Laravel untuk pencatatan event keamanan (null = default logging channel)
    'log_channel' => env('GUARD_LOG_CHANNEL', 'guard'),

    /*
    |--------------------------------------------------------------------------
    | 2. Integrasi Control Plane (WAF Centralized Hub)
    |--------------------------------------------------------------------------
    | Koneksi aplikasi (tenant) ke server pusat kendali AppGuard Control Plane.
    | Digunakan untuk sinkronisasi kebijakan jarak jauh, heartbeat, dan telemetri.
    */
    'control_plane' => [
        'url'        => env('GUARD_URL'),
        'app_key'    => env('GUARD_KEY'),
        'app_secret' => env('GUARD_SECRET'),
        'public_key' => env('GUARD_PUBKEY'),
        'timeout'    => (int) env('GUARD_TIMEOUT', 3), // Batas waktu request ke Control Plane (detik)
    ],


    /*
    |--------------------------------------------------------------------------
    | 3. Pengecualian Jaringan (IP Allowlist / Bypass)
    |--------------------------------------------------------------------------
    | Daftar alamat IP tunggal atau subnet CIDR yang sepenuhnya dibebaskan dari
    | seluruh inspeksi detektor WAF dan kalkulasi skor reputasi.
    | Contoh: ['127.0.0.1', '192.168.1.0/24', '10.0.0.0/8']
    */
    'allowlist' => [
        // '127.0.0.1',
    ],

    // Pengecualian (Exclusion) multi-dimensi dari inspeksi WAF
    'exclusions' => [
        'ips'     => [], // ['10.0.0.0/8']
        'paths'   => [], // ['health', 'up', 'webhook/*']
        'fields'  => [], // ['content_html', '*signature*'] — diabaikan oleh semua detektor input
        'headers' => [], // ['x-internal-probe' => 'secret']
        'users'   => [], // [1, 'admin-uuid']
        'roles'   => [], // ['superadmin']
    ],


    /*
    |--------------------------------------------------------------------------
    | 4. Ambang Batas Skor & Profil Penalti (Thresholds & Profiles)
    |--------------------------------------------------------------------------
    | Sistem penilaian berbasis reputasi (0 - 100+):
    | - Skor akumulasi >= throttle : Laju request mulai dibatasi (HTTP 429)
    | - Skor akumulasi >= block    : Akses ditolak langsung (HTTP 403)
    */
    'thresholds' => [
        'throttle' => (int) env('GUARD_THROTTLE', 50),
        'block'    => (int) env('GUARD_BLOCK', 100),
    ],

    // Ambang batas khusus untuk endpoint sensitif & preset siap pakai (strict, balanced, monitor)
    'profiles' => [
        'strict' => [
            'throttle' => 30,
            'block'    => 70,
            'mode'     => 'enforce',
            'paths'    => ['login', 'register', 'password/*', 'api/login', 'api/auth/*'],
        ],
        'balanced' => [
            'throttle' => 50,
            'block'    => 100,
            'mode'     => 'enforce',
            'paths'    => [],
        ],
        'monitor' => [
            'throttle' => 50,
            'block'    => 100,
            'mode'     => 'monitor',
            'paths'    => [],
        ],
    ],

    // Masa retensi skor reputasi IP / identitas dalam cache (dalam detik, misal 1800 = 30 menit)
    'reputation_ttl' => (int) env('GUARD_REPUTATION_TTL', 1800),

    // Maksimal request per menit yang diizinkan ketika klien berstatus 'throttle'
    'throttle_per_minute' => 10,

    // Nama input formulir yang dikenali sebagai identitas akun (digunakan oleh brute force detector)
    'identifier_keys' => ['email', 'username', 'login'],


    /*
    |--------------------------------------------------------------------------
    | 5. Proteksi Akun Pengguna (Auto-Banned & Force Logout)
    |--------------------------------------------------------------------------
    | Mengambil tindakan tegas terhadap pengguna terautentikasi yang melanggar aturan.
    | Terbagi menjadi dua tingkatan (Tier):
    | - Tier 1 (Soft Action) : Memutus sesi login secara paksa (Force Logout)
    | - Tier 2 (Hard Action) : Memperbarui kolom status akun di database (Auto-Ban)
    */
    'user_ban' => [
        // Aktifkan mekanisme ban otomatis akun pengguna
        'enabled' => env('GUARD_BAN_ENABLED', true),

        // Ambang batas skor pelanggaran yang memicu tindakan ban akun
        'threshold' => (int) env('GUARD_BAN_THRESHOLD', 100),

        // Durasi penyimpanan status banned di layer cache (604800 detik = 7 hari)
        'duration' => 604800,

        // Rule yang BERHAK memicu Hard Ban (Tier 2). Pelanggaran di luar ini hanya memicu Force Logout (Tier 1)
        'critical_rules' => [
            'sqli',
            'malicious_upload',
            'path_traversal',
        ],

        // Tingkat keparahan (severity) minimum yang berhak memicu Hard Ban
        'ban_severities' => [
            'critical',
        ],

        // Batas maksimal akumulasi poin per rule dalam 1 jendela reputasi
        'rule_score_caps' => [
            'high_entropy'        => 35,
            'parameter_tampering' => 70,
            'scanner_fuzzing'     => 50,
            'captcha_abuse'       => 35,
        ],

        // Model Eloquent pengguna yang digunakan aplikasi host
        'model' => App\Models\User::class,

        // Kolom database yang dimutasi saat akun di-banned. Format: ['kolom' => nilai]
        // Contoh: ['status' => 'banned'] atau ['c_status' => 1] atau ['is_active' => false]
        'attributes' => [
            // 'is_active' => false,
        ],

        // Route pengalihan saat pengguna yang di-ban atau di-logout paksa mencoba mengakses aplikasi
        'redirect_route' => 'login',
    ],


    /*
    |--------------------------------------------------------------------------
    | 6. Penyimpanan Dataset Forensik (Vulnerability Telemetry)
    |--------------------------------------------------------------------------
    | Menyimpan bukti percobaan serangan yang tervalidasi ke dalam berkas JSONL
    | untuk kebutuhan audit keamanan internal dan pelatihan model Machine Learning.
    | Anda cukup menentukan direktori penyimpanannya saja (nama 'vulnerabilities.jsonl'
    | akan otomatis ditambahkan), atau dapat menyertakan nama berkas secara penuh.
    */
    'vulnerability' => [
        // Driver penyimpanan insiden: 'jsonl' (file), 'array' (in-memory test), atau 'null' (nonaktif)
        'driver'       => env('GUARD_VULNERABILITY_DRIVER', 'jsonl'),
        'dataset_path' => env('GUARD_DATASET_PATH', storage_path('app/guard')),
    ],


    /*
    |--------------------------------------------------------------------------
    | 7. Bobot Skor Pelanggaran (Violation Rules Metadata)
    |--------------------------------------------------------------------------
    | Menetapkan poin penalti (points) dan tingkat keparahan (severity) untuk setiap
    | jenis insiden keamanan yang dilaporkan oleh detektor atau controller aplikasi.
    */
    'rules' => [
        'sqli' => [
            'points'      => 100, // Langsung memicu blokir & auto-ban
            'severity'    => 'critical',
            'description' => 'Percobaan eksploitasi SQL Injection terdeteksi',
        ],
        'malicious_upload' => [
            'points'      => 50,
            'severity'    => 'critical',
            'description' => 'Percobaan unggah berkas mencurigakan atau berbahaya',
        ],
        'path_traversal' => [
            'points'      => 50,
            'severity'    => 'critical',
            'description' => 'Percobaan Directory / Path Traversal pada penanganan berkas',
        ],
        'xss' => [
            'points'      => 50,
            'severity'    => 'high',
            'description' => 'Percobaan injeksi skrip berbahaya (Cross-Site Scripting)',
        ],
        'idor' => [
            'points'      => 25,
            'severity'    => 'medium',
            'description' => 'Percobaan akses tidak sah pada data/berkas milik akun lain (IDOR)',
        ],
        'parameter_tampering' => [
            'points'      => 35,
            'severity'    => 'medium',
            'description' => 'Manipulasi parameter form atau field terlarang (Mass Assignment)',
        ],
        'scanner_fuzzing' => [
            'points'      => 50,
            'severity'    => 'medium',
            'description' => 'Aktivitas automated vulnerability scanning / fuzzing URL terdeteksi',
        ],
        'captcha_abuse' => [
            'points'      => 35,
            'severity'    => 'medium',
            'description' => 'Percobaan manipulasi atau replay token CAPTCHA secara tidak sah',
        ],
        'high_entropy' => [
            'points'      => 35,
            'severity'    => 'low',
            'description' => 'Muatan teks anomali dengan tingkat keacakan berlebih (Shannon Entropy)',
        ],
    ],


    /*
    |--------------------------------------------------------------------------
    | 8. Detektor Bawaan (Built-in WAF Detectors)
    |--------------------------------------------------------------------------
    | Konfigurasi parameter operasional masing-masing modul inspeksi bawaan.
    */
    'detectors' => [

        // 1. Jebakan bot / scanner web otomatis (Honeypot paths)
        'honeypot' => [
            'enabled' => true,
            'score'   => 100,
            'paths'   => [
                '.env*',
                '.git*',
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

        // 2. Pencegahan percobaan login berulang (Brute Force)
        'brute_force' => [
            'enabled'            => true,
            'paths'              => ['login', 'api/login', 'api/auth/*', 'password/email'],
            'window'             => 900, // Jendela waktu monitoring (15 menit)
            'max_per_ip'         => 20,  // Batas gagal per IP
            'max_per_identifier' => 8,   // Batas gagal per username/email
            'max_per_pair'       => 5,   // Batas gagal per pasangan (IP + username)
            'score_ip'           => 100,
            'score_identifier'   => 60,
            'score_pair'         => 100,
        ],

        // 3. Deteksi pemindaian endpoint tak terdaftar secara masif (Enumerasi 403 / 404)
        'denied_access' => [
            'enabled'      => true,
            'statuses'     => [403, 404],
            'window'       => 60, // 1 menit
            'threshold'    => 15, // Maksimal respon error sebelum diberi penalti
            'score'        => 40,
            'ignore_paths' => ['favicon.ico', 'robots.txt', '*.map', 'apple-touch-icon*'],
        ],

        // 4. Deteksi manipulasi path berkas (../, ..\, null-byte)
        'path_traversal' => [
            'enabled' => true,
            'score'   => 50,
        ],

        // 5. Pemindaian pola injeksi payload SQLi & XSS pada query & request body
        'malicious_payload' => [
            'enabled'    => true,
            'sqli_score' => 100,
            'xss_score'  => 50,
            // Field formulir yang dikecualikan dari scanning (misal: WYSIWYG editor artikel / HTML)
            'safe_fields' => [
                // 'content', 'deskripsi', 'body_html',
            ],
        ],

        // 6. Deteksi injeksi field parameter berbahaya (misal: is_admin, role, status)
        'parameter_tampering' => [
            'enabled'          => true,
            'score'            => 35,
            'forbidden_fields' => [
                'is_admin',
                'role',
                'role_id',
                'status_id',
                'is_superuser',
            ],
        ],

        // 7. Deteksi anomali Shannon Entropy (payload ter-obfuskasi) dan scanner fuzzing
        'anomaly' => [
            'enabled'            => true,
            'entropy_threshold'  => 4.5,
            'entropy_min_length' => 120,
            'entropy_score'      => 35,
            'fuzzing_window'     => 30,
            'fuzzing_threshold'  => 15,
            'fuzzing_score'      => 50,
            // Field teks panjang yang diizinkan memiliki variasi karakter bebas
            'safe_fields' => [
                // 'catatan', 'keterangan', 'alasan',
            ],
        ],
    ],


    /*
    |--------------------------------------------------------------------------
    | 9. Detektor Kustom (Custom Detectors)
    |--------------------------------------------------------------------------
    | Daftarkan kelas detektor tambahan buatan Anda yang mengimplementasikan:
    | `AppGuard\Core\Contracts\Detector`.
    |
    | Panduan implementasi dapat dilihat pada dokumentasi package `docs/02-detectors-scoring.md`.
    */
    'custom_detectors' => [
        // App\Security\Detectors\BlockDisallowedUserAgentDetector::class,
    ],

];
