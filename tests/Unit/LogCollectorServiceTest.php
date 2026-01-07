<?php

namespace Tests\Unit;

use App\Services\LogCollectorService;
use Tests\TestCase;

class LogCollectorServiceTest extends TestCase
{
    private LogCollectorService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new LogCollectorService();
    }

    public function test_parse_valid_log_line(): void
    {
        $logLine = '192.168.1.100 - - [07/Jan/2026:10:30:45 +0000] "GET /api/users?page=1 HTTP/1.1" 200 1234 "https://example.com/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"';

        $result = $this->service->parseLogLine($logLine);

        $this->assertIsArray($result);
        $this->assertEquals('192.168.1.100', $result['ip']);
        $this->assertEquals('GET', $result['method']);
        $this->assertEquals('/api/users', $result['uri']['path']);
        $this->assertEquals('page=1', $result['uri']['query']);
        $this->assertEquals(200, $result['status']);
        $this->assertEquals(1234, $result['size']);
        $this->assertEquals('https://example.com/dashboard', $result['referer']);
    }

    public function test_parse_log_line_with_sql_injection_attempt(): void
    {
        $logLine = '192.168.1.50 - - [07/Jan/2026:11:00:00 +0000] "GET /page?id=1\' OR \'1\'=\'1 HTTP/1.1" 403 0 "-" "sqlmap/1.0"';

        $result = $this->service->parseLogLine($logLine);

        $this->assertIsArray($result);
        $this->assertEquals('192.168.1.50', $result['ip']);
        // Note: URL-encoded spaces or actual spaces get parsed up to first space
        $this->assertEquals('/page', $result['uri']['path']);
        $this->assertEquals('sqlmap/1.0', $result['user_agent']);
        $this->assertEquals(403, $result['status']);
    }

    public function test_parse_log_line_with_xss_attempt(): void
    {
        $logLine = '10.0.0.5 - - [07/Jan/2026:12:00:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 400 0 "-" "Chrome/90.0"';

        $result = $this->service->parseLogLine($logLine);

        $this->assertIsArray($result);
        $this->assertStringContainsString('<script>', $result['uri']['full']);
    }

    public function test_parse_invalid_log_line(): void
    {
        $logLine = 'This is not a valid log line';

        $result = $this->service->parseLogLine($logLine);

        $this->assertNull($result);
    }

    public function test_parse_log_line_without_referer(): void
    {
        $logLine = '127.0.0.1 - - [07/Jan/2026:13:00:00 +0000] "POST /api/login HTTP/1.1" 200 512 "-" "curl/7.68.0"';

        $result = $this->service->parseLogLine($logLine);

        $this->assertIsArray($result);
        $this->assertNull($result['referer']);
        $this->assertEquals('curl/7.68.0', $result['user_agent']);
    }

    public function test_parse_post_request(): void
    {
        $logLine = '192.168.1.200 - - [07/Jan/2026:14:00:00 +0000] "POST /api/data HTTP/1.1" 201 2048 "https://app.example.com" "axios/0.21.1"';

        $result = $this->service->parseLogLine($logLine);

        $this->assertIsArray($result);
        $this->assertEquals('POST', $result['method']);
        $this->assertEquals(201, $result['status']);
    }

    public function test_parse_large_response_size(): void
    {
        $logLine = '203.0.113.50 - - [07/Jan/2026:15:00:00 +0000] "GET /download/file.zip HTTP/1.1" 200 104857600 "-" "wget/1.20.3"';

        $result = $this->service->parseLogLine($logLine);

        $this->assertIsArray($result);
        $this->assertEquals(104857600, $result['size']); // 100MB
    }
}
