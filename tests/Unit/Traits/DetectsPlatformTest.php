<?php

namespace Tests\Unit\Traits;

use App\Traits\DetectsPlatform;
use PHPUnit\Framework\TestCase;

class DetectsPlatformTest extends TestCase
{
    public function test_is_windows_returns_boolean()
    {
        $class = new class {
            use DetectsPlatform;
        };

        $this->assertIsBool($class->isWindows());
    }

    public function test_is_windows_matches_environment()
    {
        $class = new class {
            use DetectsPlatform;
        };

        $expected = (defined('PHP_OS_FAMILY') && is_string(PHP_OS_FAMILY)) ? PHP_OS_FAMILY === 'Windows' : DIRECTORY_SEPARATOR === '\\';

        $this->assertEquals($expected, $class->isWindows());
    }
}
