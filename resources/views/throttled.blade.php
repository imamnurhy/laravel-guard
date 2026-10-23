<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>429 — Batas Permintaan Terlampaui</title>
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
            background: #fef3c7;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #d97706;
        }

        .icon-wrapper svg {
            width: 24px;
            height: 24px;
        }

        .code-badge {
            display: inline-block;
            font-size: 0.8125rem;
            font-weight: 600;
            color: #d97706;
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

        .countdown-box {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.75rem;
        }

        .countdown-title {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.025em;
            color: #64748b;
            margin-bottom: 0.25rem;
            font-weight: 600;
        }

        .countdown-timer {
            font-size: 1.75rem;
            font-weight: 700;
            color: #0f172a;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
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

        .btn-primary:hover:not(:disabled) {
            background: #1d4ed8;
            border-color: #1d4ed8;
        }

        .btn-primary:disabled {
            background: #94a3b8;
            border-color: #94a3b8;
            cursor: not-allowed;
            opacity: 0.7;
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
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
            </div>

            <div class="code-badge">429 &bull; TERLALU BANYAK PERMINTAAN</div>
            <h1>Laju Permintaan Dibatasi</h1>
            <p class="desc">
                Anda mengirimkan terlalu banyak permintaan dalam waktu singkat. Mohon tunggu sejenak hingga batas waktu cooldown selesai.
            </p>

            <div class="countdown-box">
                <div class="countdown-title">Dapat mencoba kembali dalam</div>
                <div class="countdown-timer" id="timer">{{ max(1, (int) ($retryAfter ?? 60)) }}s</div>
            </div>

            <div class="actions">
                <button type="button" id="btn-reload" onclick="window.location.reload()" class="btn btn-primary" disabled>
                    Muat Ulang Halaman
                </button>
                <a href="{{ url('/') }}" class="btn btn-secondary">
                    Ke Beranda
                </a>
            </div>

            <div class="footer">
                Sistem Keamanan Aplikasi &bull; AppGuard
            </div>
        </div>
    </div>

    <script>
        (function() {
            var seconds = parseInt("{{ max(1, (int) ($retryAfter ?? 60)) }}", 10) || 60;
            var timerEl = document.getElementById('timer');
            var btnReload = document.getElementById('btn-reload');

            var interval = setInterval(function() {
                seconds--;
                if (seconds <= 0) {
                    clearInterval(interval);
                    timerEl.textContent = "Siap";
                    timerEl.style.color = "#16a34a";
                    btnReload.removeAttribute('disabled');
                    btnReload.textContent = "Coba Lagi Sekarang";
                } else {
                    timerEl.textContent = seconds + "s";
                }
            }, 1000);
        })();
    </script>
</body>
</html>
