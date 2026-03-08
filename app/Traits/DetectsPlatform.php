<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the current platform is Windows.
     *
     * Note: This trait is intended only for native OS environments.
     * On Linux systems running WSL (Windows Subsystem for Linux),
     * this will return false as the underlying PHP environment is Linux.
     *
     * @return bool
     */
    private function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows' || str_starts_with(strtoupper(PHP_OS), 'WIN');
    }
}
