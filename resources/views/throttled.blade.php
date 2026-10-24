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
            background: #ffffff;
            color: #111827;
            padding: 2rem 1.5rem;
        }

        .wrapper {
            width: 100%;
            max-width: 480px;
        }

        .code {
            font-size: 0.8125rem;
            font-weight: 600;
            color: #d97706;
            letter-spacing: 0.05em;
            margin-bottom: 0.625rem;
            text-transform: uppercase;
        }

        h1 {
            font-size: 1.625rem;
            font-weight: 600;
            color: #111827;
            letter-spacing: -0.025em;
            margin-bottom: 0.75rem;
            line-height: 1.3;
        }

        p.desc {
            font-size: 0.9375rem;
            line-height: 1.6;
            color: #4b5563;
            margin-bottom: 1.5rem;
        }

        .timer-info {
            font-size: 0.875rem;
            color: #6b7280;
            margin-bottom: 2rem;
        }

        .timer-val {
            font-weight: 600;
            color: #111827;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        }

        .actions {
            display: flex;
            gap: 1rem;
            align-items: center;
            margin-bottom: 2.5rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            font-size: 0.875rem;
            font-weight: 500;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            transition: all 0.15s ease;
            cursor: pointer;
            border: none;
        }

        .btn-primary {
            background: #111827;
            color: #ffffff;
        }

        .btn-primary:hover:not(:disabled) {
            background: #374151;
        }

        .btn-primary:disabled {
            background: #e5e7eb;
            color: #9ca3af;
            cursor: not-allowed;
        }

        .btn-link {
            color: #4b5563;
            padding: 0.5rem 0.25rem;
            background: transparent;
        }

        .btn-link:hover {
            color: #111827;
            text-decoration: underline;
        }

        .meta {
            border-top: 1px solid #f3f4f6;
            padding-top: 1.25rem;
            font-size: 0.75rem;
            color: #9ca3af;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="code">429 &bull; Terlalu Banyak Permintaan</div>
        <h1>Laju Permintaan Dibatasi</h1>
        <p class="desc">
            Anda mengirimkan terlalu banyak permintaan dalam waktu singkat. Mohon tunggu sejenak hingga batas cooldown selesai sebelum mencoba kembali.
        </p>

        <div class="timer-info">
            Dapat mencoba kembali dalam <span class="timer-val" id="timer">{{ max(1, (int) ($retryAfter ?? 60)) }} detik</span>
        </div>

        <div class="actions">
            <button type="button" id="btn-reload" onclick="window.location.reload()" class="btn btn-primary" disabled>Muat Ulang Halaman</button>
            <a href="{{ url('/') }}" class="btn btn-link">Ke Beranda</a>
        </div>

        <div class="meta">
            IP: {{ request()->ip() ?? 'N/A' }} &bull; {{ now()->setTimezone(config('app.timezone', 'UTC'))->format('d M Y, H:i T') }} &bull; {{ config('app.name', 'Sistem Keamanan') }}
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
                    timerEl.textContent = "Sekarang (Siap)";
                    timerEl.style.color = "#16a34a";
                    btnReload.removeAttribute('disabled');
                    btnReload.textContent = "Coba Lagi Sekarang";
                } else {
                    timerEl.textContent = seconds + " detik";
                }
            }, 1000);
        })();
    </script>
</body>
</html>
