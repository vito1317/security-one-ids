<?php

namespace Tests\Unit;

use App\Models\IdsSignature;
use App\Services\Detection\SignatureEngine;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class SignatureEngineTest extends TestCase
{
    use RefreshDatabase;
    
    private SignatureEngine $engine;

    protected function setUp(): void
    {
        parent::setUp();
        $this->engine = new SignatureEngine();
        
        // Seed test signatures
        IdsSignature::create([
            'name' => 'Test SQL Injection',
            'pattern' => 'union.*select',
            'category' => 'sqli',
            'severity' => 'critical',
            'match_uri' => true,
            'match_user_agent' => false,
            'match_referer' => false,
            'enabled' => true,
        ]);

        IdsSignature::create([
            'name' => 'Test XSS',
            'pattern' => '<script.*>',
            'category' => 'xss',
            'severity' => 'critical',
            'match_uri' => true,
            'match_user_agent' => false,
            'match_referer' => true,
            'enabled' => true,
        ]);

        IdsSignature::create([
            'name' => 'Test Scanner',
            'pattern' => 'sqlmap',
            'category' => 'scanner',
            'severity' => 'high',
            'match_uri' => false,
            'match_user_agent' => true,
            'match_referer' => false,
            'enabled' => true,
        ]);
    }

    public function test_detect_sql_injection_in_uri(): void
    {
        $logData = [
            'ip' => '192.168.1.1',
            'uri' => ['full' => '/page?id=1 UNION SELECT * FROM users'],
            'method' => 'GET',
            'user_agent' => 'Mozilla/5.0',
        ];

        $result = $this->engine->analyze($logData);

        $this->assertNotNull($result);
        $this->assertTrue($result['detected']);
        $this->assertEquals('sqli', $result['category']);
        $this->assertEquals('critical', $result['severity']);
        $this->assertEquals('uri', $result['matched_location']);
    }

    public function test_detect_xss_in_uri(): void
    {
        $logData = [
            'ip' => '192.168.1.1',
            'uri' => ['full' => '/search?q=<script>alert(1)</script>'],
            'method' => 'GET',
            'user_agent' => 'Mozilla/5.0',
        ];

        $result = $this->engine->analyze($logData);

        $this->assertNotNull($result);
        $this->assertTrue($result['detected']);
        $this->assertEquals('xss', $result['category']);
        $this->assertEquals('critical', $result['severity']);
    }

    public function test_detect_scanner_in_user_agent(): void
    {
        $logData = [
            'ip' => '192.168.1.1',
            'uri' => ['full' => '/api/users'],
            'method' => 'GET',
            'user_agent' => 'sqlmap/1.0',
        ];

        $result = $this->engine->analyze($logData);

        $this->assertNotNull($result);
        $this->assertTrue($result['detected']);
        $this->assertEquals('scanner', $result['category']);
        $this->assertEquals('user_agent', $result['matched_location']);
    }

    public function test_no_detection_for_clean_request(): void
    {
        $logData = [
            'ip' => '192.168.1.1',
            'uri' => ['full' => '/api/users?page=1'],
            'method' => 'GET',
            'user_agent' => 'Mozilla/5.0 Chrome/90.0',
        ];

        $result = $this->engine->analyze($logData);

        $this->assertNull($result);
    }

    public function test_analyze_batch_of_logs(): void
    {
        $logs = collect([
            [
                'uri' => ['full' => '/page?id=1 UNION SELECT'],
                'user_agent' => 'Browser',
            ],
            [
                'uri' => ['full' => '/search?q=<script>alert()</script>'],
                'user_agent' => 'Browser',
            ],
            [
                'uri' => ['full' => '/api/users'],
                'user_agent' => 'Browser',
            ],
        ]);

        $results = $this->engine->analyzeBatch($logs);

        $this->assertEquals(2, $results->count()); // 2 attacks detected
    }

    public function test_disabled_signature_not_matched(): void
    {
        // Disable all signatures
        IdsSignature::query()->update(['enabled' => false]);

        $logData = [
            'uri' => ['full' => '/page?id=1 UNION SELECT'],
            'user_agent' => 'sqlmap/1.0',
        ];

        $result = $this->engine->analyze($logData);

        $this->assertNull($result);
    }

    public function test_built_in_signatures_available(): void
    {
        $builtIn = SignatureEngine::getBuiltInSignatures();

        $this->assertIsArray($builtIn);
        $this->assertGreaterThan(10, count($builtIn));
        
        // Check structure
        $first = $builtIn[0];
        $this->assertArrayHasKey('name', $first);
        $this->assertArrayHasKey('pattern', $first);
        $this->assertArrayHasKey('category', $first);
        $this->assertArrayHasKey('severity', $first);
    }

    public function test_case_insensitive_matching(): void
    {
        $logData = [
            'uri' => ['full' => '/page?id=1 UNION SELECT'], // Uppercase
            'user_agent' => 'Browser',
        ];

        $result = $this->engine->analyze($logData);

        $this->assertNotNull($result);
        $this->assertEquals('sqli', $result['category']);
    }
}
