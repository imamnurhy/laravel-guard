<?php

namespace AppGuard\Core\Contracts;

interface DynamicRuleStore
{
    /**
     * Tambahkan path honeypot dinamis yang disinkronkan dari Control Plane.
     *
     * @param string[] $paths
     */
    public function addDynamicHoneypots(array $paths): void;

    /**
     * Ambil seluruh path honeypot dinamis yang tersimpan di cache.
     *
     * @return string[]
     */
    public function getDynamicHoneypots(): array;

    /**
     * Set dynamic thresholds (mis. per-path profile / score threshold).
     */
    public function setDynamicThresholds(array $thresholds): void;

    /**
     * Ambil dynamic thresholds dari cache.
     */
    public function getDynamicThresholds(): array;

    /**
     * Simpan kebijakan keamanan (policy) terpusat dari Control Plane.
     */
    public function setPolicy(array $policy): void;

    /**
     * Ambil kebijakan keamanan terpusat dari cache.
     */
    public function getPolicy(): ?array;
}
