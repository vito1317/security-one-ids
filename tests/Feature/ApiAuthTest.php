<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Tests\TestCase;
use Illuminate\Support\Facades\Config;

class ApiAuthTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Set a known token for testing
        putenv('AGENT_TOKEN=test-agent-token');
    }

    public function test_auth_logic_rejects_missing_token()
    {
        // Missing token
        $this->postJson('/api/rules/update', [])->assertStatus(401);

        // Empty token
        $this->postJson('/api/rules/update?token=', [])->assertStatus(401);

        // Wrong token
        $this->postJson('/api/rules/update?token=wrong-token', [])->assertStatus(401);
    }
}
