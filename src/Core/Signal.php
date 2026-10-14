<?php

namespace AppGuard\Core;

/** Satu sinyal mencurigakan dari sebuah detector. */
final class Signal
{
    public function __construct(
        public readonly string $detector,
        public readonly int $score,
        public readonly string $reason,
        /** true = skor disimpan ke reputasi (IP/user) dan ikut dihitung di request berikutnya */
        public readonly bool $persist = false,
    ) {
    }
}
