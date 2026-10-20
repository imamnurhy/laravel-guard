<?php

namespace AppGuard\Attributes;

use Attribute;

/**
 * PHP Attribute untuk menetapkan profile, detektor, atau threshold khusus pada controller/method.
 *
 * Contoh:
 *   #[GuardProfile('strict')]
 *   #[GuardProfile('monitor', detectors: ['honeypot', 'malicious_payload'], block: 80)]
 *   #[GuardProfile(bypass: true)]
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final class GuardProfile
{
    /**
     * @param string[]|null $detectors Daftar nama detektor yang diaktifkan (null = semua).
     */
    public function __construct(
        public readonly ?string $profile = null,
        public readonly ?int $throttle = null,
        public readonly ?int $block = null,
        public readonly ?string $mode = null,
        public readonly ?array $detectors = null,
        public readonly bool $bypass = false,
    ) {
    }

    /** @return array<string, mixed> */
    public function toOverrides(): array
    {
        return array_filter([
            'profile' => $this->profile,
            'throttle' => $this->throttle,
            'block' => $this->block,
            'mode' => $this->mode,
            'detectors' => $this->detectors,
            'bypass' => $this->bypass ?: null,
        ], fn ($v) => $v !== null);
    }
}

