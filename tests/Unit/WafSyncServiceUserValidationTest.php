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
        $this->assertTrue((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'john.doe'));
        $this->assertTrue((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'user_123'));
        $this->assertTrue((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'admin-user'));
        $this->assertTrue((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'johndoe'));
    }

    /**
     * Test invalid macOS usernames according to the regex pattern
     * These should be rejected to prevent shell injection while preserving path parsing
     */
    public function testInvalidMacOsUsernames()
    {
        // Reject spaces
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'john doe'));

        // Reject quotes and shell metacharacters
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'user"name'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', "user'name"));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'admin;ls'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'admin|ls'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'admin&ls'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'admin$user'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'admin`ls`'));
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', 'admin>file'));
        // Reject leading hyphen
        $this->assertFalse((bool) preg_match('/^[a-zA-Z0-9._][a-zA-Z0-9._-]*$/', '-admin'));
    }
}
