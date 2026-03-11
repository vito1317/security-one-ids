<?php

namespace App\Traits;

trait PlatformInfo
{
    /**
     * Determine if the current platform is Windows.
     *
     * @return bool
     */
    public function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }
}
