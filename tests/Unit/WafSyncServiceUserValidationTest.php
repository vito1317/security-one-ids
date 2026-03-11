<?php

namespace Tests\Unit;

use PHPUnit\Framework\TestCase;

class WafSyncServiceUserValidationTest extends TestCase
{
    /**
     * Test valid macOS usernames according to the regex pattern
     */
    public function testValidMacOsUsernames()
    {
        $pattern = \App\Services\WafSyncService::MACOS_USERNAME_REGEX;
        $this->assertTrue((bool) preg_match($pattern, 'john.doe'));
        $this->assertTrue((bool) preg_match($pattern, 'user_123'));
        $this->assertTrue((bool) preg_match($pattern, 'admin-user'));
        $this->assertTrue((bool) preg_match($pattern, 'johndoe'));
    }

    /**
     * Test invalid macOS usernames according to the regex pattern
     * These should be rejected to prevent shell injection while preserving path parsing
     */
    public function testInvalidMacOsUsernames()
    {
        $pattern = \App\Services\WafSyncService::MACOS_USERNAME_REGEX;
        // Reject spaces
        $this->assertFalse((bool) preg_match($pattern, 'john doe'));

        // Reject quotes and shell metacharacters
        $this->assertFalse((bool) preg_match($pattern, 'user"name'));
        $this->assertFalse((bool) preg_match($pattern, "user'name"));
        $this->assertFalse((bool) preg_match($pattern, 'admin;ls'));
        $this->assertFalse((bool) preg_match($pattern, 'admin|ls'));
        $this->assertFalse((bool) preg_match($pattern, 'admin&ls'));
        $this->assertFalse((bool) preg_match($pattern, 'admin$user'));
        $this->assertFalse((bool) preg_match($pattern, 'admin`ls`'));
        $this->assertFalse((bool) preg_match($pattern, 'admin>file'));
    }
}
