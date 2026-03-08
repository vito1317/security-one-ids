<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Cache the platform check result.
     *
     * @var bool|null
     */
    private ?bool $isWindowsCached = null;

    /**
     * Get platform family with backward-compatible fallback.
     *
     * @return string
     */
    protected function platformFamily(): string
    {
        if (defined('PHP_OS_FAMILY')) {
            return PHP_OS_FAMILY;
        }

        return stripos(PHP_OS, 'WIN') === 0 ? 'Windows' : PHP_OS;
    }

    /**
     * Determine if the current platform is Windows.
     *
     * @return bool
     */
    protected function isWindows(): bool
    {
        if ($this->isWindowsCached !== null) {
            return $this->isWindowsCached;
        }

        $this->isWindowsCached = $this->platformFamily() === 'Windows';

        return $this->isWindowsCached;
    }
}
