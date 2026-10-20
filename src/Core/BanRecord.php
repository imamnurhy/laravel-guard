<?php

namespace AppGuard\Core;

/**
 * Snapshot metadata satu ban/blokir (IP atau user) yang tersimpan di indeks BanRegistry.
 *
 * Key ban sesungguhnya tetap berada di Store (Redis/cache ber-TTL); record ini hanya
 * indeks agar daftar ban dapat ditampilkan tanpa SCAN/KEYS yang mahal.
 */
final class BanRecord
{
    public const TYPE_IP = 'ip';
    public const TYPE_USER = 'user';

    public function __construct(
        public readonly string $type,
        public readonly string $subject,
        public readonly string $reason = '',
        public readonly string $source = 'manual',
        public readonly int $score = 0,
        public readonly int $bannedAt = 0,
        public readonly ?int $expiresAt = null,
        public readonly ?string $ip = null,
        public readonly array $meta = [],
    ) {
    }

    public static function key(string $type, string|int $subject): string
    {
        return "{$type}:{$subject}";
    }

    public function id(): string
    {
        return self::key($this->type, $this->subject);
    }

    public function isPermanent(): bool
    {
        return $this->expiresAt === null;
    }

    public function isExpired(?int $now = null): bool
    {
        return $this->expiresAt !== null && $this->expiresAt <= ($now ?? time());
    }

    /** Sisa waktu ban dalam detik (null = permanen). */
    public function remaining(?int $now = null): ?int
    {
        return $this->expiresAt === null ? null : max(0, $this->expiresAt - ($now ?? time()));
    }

    /** Total durasi ban dalam detik (null = permanen). */
    public function duration(): ?int
    {
        return $this->expiresAt === null ? null : max(1, $this->expiresAt - $this->bannedAt);
    }

    public function label(): string
    {
        $label = $this->meta['label'] ?? null;

        return $label && (string) $label !== $this->subject ? "{$this->subject} ({$label})" : $this->subject;
    }

    public function toArray(): array
    {
        return [
            'type' => $this->type,
            'subject' => $this->subject,
            'reason' => $this->reason,
            'source' => $this->source,
            'score' => $this->score,
            'banned_at' => $this->bannedAt,
            'expires_at' => $this->expiresAt,
            'ip' => $this->ip,
            'meta' => $this->meta,
        ];
    }

    public static function fromArray(array $data): self
    {
        return new self(
            (string) ($data['type'] ?? self::TYPE_IP),
            (string) ($data['subject'] ?? ''),
            (string) ($data['reason'] ?? ''),
            (string) ($data['source'] ?? 'manual'),
            (int) ($data['score'] ?? 0),
            (int) ($data['banned_at'] ?? 0),
            isset($data['expires_at']) ? (int) $data['expires_at'] : null,
            isset($data['ip']) ? (string) $data['ip'] : null,
            (array) ($data['meta'] ?? []),
        );
    }
}

