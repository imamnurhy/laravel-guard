<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>403 — Akses Ditolak</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }

        body {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: #f8fafc;
            color: #1e293b;
            padding: 1.5rem;
        }

        .container {
            width: 100%;
            max-width: 480px;
        }

        .card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 2.25rem 2rem;
            text-align: center;
        }

        .icon-wrapper {
            width: 48px;
            height: 48px;
            margin: 0 auto 1.25rem;
            border-radius: 50%;
            background: #fee2e2;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #dc2626;
        }

        .icon-wrapper svg {
            width: 24px;
            height: 24px;
        }

        .code-badge {
            display: inline-block;
            font-size: 0.8125rem;
            font-weight: 600;
            color: #dc2626;
            margin-bottom: 0.5rem;
            letter-spacing: 0.025em;
        }

        h1 {
            font-size: 1.375rem;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 0.75rem;
        }

        p.desc {
            font-size: 0.875rem;
            line-height: 1.55;
            color: #64748b;
            margin-bottom: 1.5rem;
        }

        .meta-box {
            background: #f1f5f9;
            border-radius: 8px;
            padding: 0.875rem 1rem;
            margin-bottom: 1.75rem;
            font-size: 0.8125rem;
            display: flex;
            justify-content: space-between;
            text-align: left;
        }

        .meta-item .label {
            display: block;
            color: #64748b;
            font-size: 0.6875rem;
            margin-bottom: 0.2rem;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.025em;
        }

        .meta-item .value {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            color: #334155;
            font-weight: 600;
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
            padding: 0.625rem 1.125rem;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 500;
            text-decoration: none;
            transition: background-color 0.15s ease, border-color 0.15s ease;
            cursor: pointer;
        }

        .btn-primary {
            background: #2563eb;
            color: #ffffff;
            border: 1px solid #2563eb;
        }

        .btn-primary:hover {
            background: #1d4ed8;
            border-color: #1d4ed8;
        }

        .btn-secondary {
            background: #ffffff;
            color: #475569;
            border: 1px solid #cbd5e1;
        }

        .btn-secondary:hover {
            background: #f8fafc;
            color: #1e293b;
            border-color: #94a3b8;
        }

        .footer {
            margin-top: 1.25rem;
            font-size: 0.75rem;
            color: #94a3b8;
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

            <div class="code-badge">403 &bull; AKSES DITOLAK</div>
            <h1>Akses Anda Ditahan</h1>
            <p class="desc">
                Sistem mendeteksi aktivitas atau pola permintaan yang tidak biasa dari koneksi Anda. Demi keamanan sistem, permintaan ini untuk sementara tidak dapat diproses.
            </p>

            <div class="meta-box">
                <div class="meta-item">
                    <span class="label">Alamat IP</span>
                    <span class="value">{{ request()->ip() ?? 'N/A' }}</span>
                </div>
                <div class="meta-item" style="text-align: right;">
                    <span class="label">Waktu</span>
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
                Sistem Keamanan &bull; {{ config('app.name', 'Portal Aplikasi') }}
            </div>
        </div>
    </div>
</body>
</html>

