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
        $this->assertTrue((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'john.doe'));
        $this->assertTrue((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'user_123'));
        $this->assertTrue((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'admin-user'));
        $this->assertTrue((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'johndoe'));
    }

    /**
     * Test invalid macOS usernames according to the regex pattern
     * These should be rejected to prevent shell injection while preserving path parsing
     */
    public function testInvalidMacOsUsernames()
    {
        // Reject spaces
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'john doe'));

        // Reject quotes and shell metacharacters
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'user"name'));
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, "user'name"));
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'admin;ls'));
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'admin|ls'));
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'admin&ls'));
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'admin$user'));
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'admin`ls`'));
        $this->assertFalse((bool) preg_match(\App\Services\WafSyncService::USERNAME_PATTERN, 'admin>file'));
    }
}
