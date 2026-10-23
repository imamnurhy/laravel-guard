<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>403 — Akses Dibatasi | Security Guard</title>
    <style>
        :root {
            --bg-gradient: radial-gradient(circle at 50% 0%, #1e293b 0%, #0f172a 100%);
            --card-bg: rgba(30, 41, 59, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #ef4444;
            --danger-glow: rgba(239, 68, 68, 0.25);
            --primary: #3b82f6;
            --primary-hover: #2563eb;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #0b0f19;
            background-image: var(--bg-gradient);
            color: var(--text-main);
            padding: 1.5rem;
        }

        .container {
            width: 100%;
            max-width: 520px;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            padding: 2.5rem 2rem;
            text-align: center;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 40px var(--danger-glow);
            animation: fadeIn 0.4s ease-out;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(12px) scale(0.98);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        .icon-wrapper {
            width: 72px;
            height: 72px;
            margin: 0 auto 1.5rem;
            border-radius: 50%;
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--danger);
        }

        .icon-wrapper svg {
            width: 36px;
            height: 36px;
        }

        .badge {
            display: inline-block;
            padding: 0.35rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
            margin-bottom: 1rem;
        }

        h1 {
            font-size: 1.75rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 0.75rem;
            color: #ffffff;
        }

        p.desc {
            font-size: 0.95rem;
            line-height: 1.6;
            color: var(--text-muted);
            margin-bottom: 1.75rem;
        }

        .meta-box {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 1rem;
            margin-bottom: 2rem;
            font-size: 0.825rem;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.75rem;
            text-align: left;
        }

        .meta-item span.label {
            display: block;
            color: #64748b;
            font-size: 0.75rem;
            margin-bottom: 0.2rem;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }

        .meta-item span.value {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            color: #cbd5e1;
            font-weight: 500;
        }

        .actions {
            display: flex;
            gap: 0.75rem;
            justify-content: center;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.75rem 1.25rem;
            border-radius: 10px;
            font-size: 0.875rem;
            font-weight: 600;
            text-decoration: none;
            transition: all 0.2s ease;
            cursor: pointer;
            border: none;
        }

        .btn-primary {
            background: var(--primary);
            color: #ffffff;
        }

        .btn-primary:hover {
            background: var(--primary-hover);
            transform: translateY(-1px);
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.06);
            color: #e2e8f0;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-1px);
        }

        .footer {
            margin-top: 1.5rem;
            font-size: 0.75rem;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="icon-wrapper">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                </svg>
            </div>

            <span class="badge">403 &bull; Akses Dibatasi</span>
            <h1>Akses Anda Ditahan</h1>
            <p class="desc">
                Sistem mendeteksi aktivitas atau pola permintaan yang tidak biasa dari koneksi Anda. Demi melindungi keamanan aplikasi dan data pengguna, permintaan ini untuk sementara tidak dapat diproses.
            </p>

            <div class="meta-box">
                <div class="meta-item">
                    <span class="label">Alamat IP</span>
                    <span class="value">{{ request()->ip() ?? 'N/A' }}</span>
                </div>
                <div class="meta-item">
                    <span class="label">Waktu Deteksi</span>
                    <span class="value">{{ now()->setTimezone(config('app.timezone', 'UTC'))->format('H:i:s T') }}</span>
                </div>
            </div>

            <div class="actions">
                <a href="{{ url('/') }}" class="btn btn-primary">
                    Kembali ke Beranda
                </a>
                <button type="button" onclick="window.history.back()" class="btn btn-secondary">
                    Halaman Sebelumnya
                </button>
            </div>

            <div class="footer">
                Dilindungi oleh Sistem Keamanan Terpadu &bull; Protected by AppGuard
            </div>
        </div>
    </div>
</body>
</html>
