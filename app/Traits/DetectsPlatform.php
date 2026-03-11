<?php

namespace App\Traits;

trait DetectsPlatform
{
    /**
     * Determine if the current platform is Windows.
     *
     * @return bool
     */
<<<<<<< HEAD
    public function isWindows(): bool
=======
    private function isWindows(): bool
>>>>>>> origin/main
    {
        return PHP_OS_FAMILY === 'Windows';
    }
}
