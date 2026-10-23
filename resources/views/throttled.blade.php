<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>429 — Batas Permintaan Terlampaui | Security Guard</title>
    <style>
        :root {
            --bg-gradient: radial-gradient(circle at 50% 0%, #1e293b 0%, #0f172a 100%);
            --card-bg: rgba(30, 41, 59, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --warning: #f59e0b;
            --warning-glow: rgba(245, 158, 11, 0.25);
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
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 40px var(--warning-glow);
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
            background: rgba(245, 158, 11, 0.12);
            border: 1px solid rgba(245, 158, 11, 0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--warning);
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
            background: rgba(245, 158, 11, 0.15);
            color: #fde68a;
            border: 1px solid rgba(245, 158, 11, 0.3);
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

        .countdown-box {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(245, 158, 11, 0.2);
            border-radius: 12px;
            padding: 1.25rem 1rem;
            margin-bottom: 1.75rem;
        }

        .countdown-title {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #94a3b8;
            margin-bottom: 0.35rem;
        }

        .countdown-timer {
            font-size: 2.25rem;
            font-weight: 800;
            color: #fbbf24;
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
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
            </div>

            <span class="badge">429 &bull; Terlalu Banyak Permintaan</span>
            <h1>Laju Permintaan Dibatasi</h1>
            <p class="desc">
                Anda mengirimkan terlalu banyak permintaan dalam waktu singkat. Mohon tunggu sejenak hingga batas cooldown selesai sebelum mencoba kembali.
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
                Rate Limiting & Anti-Abuse System &bull; Protected by AppGuard
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
                    timerEl.style.color = "#4ade80";
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
