<?php

namespace Tests\Unit;

use App\Services\TrafficAnalyzer;
use Tests\TestCase;

class TrafficAnalyzerTest extends TestCase
{
    private TrafficAnalyzer $analyzer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->analyzer = new TrafficAnalyzer();
    }

    public function test_calculate_qps_with_valid_logs(): void
    {
        $logs = collect([
            ['timestamp' => '2026-01-07 10:00:00', 'ip' => '192.168.1.1'],
            ['timestamp' => '2026-01-07 10:00:01', 'ip' => '192.168.1.2'],
            ['timestamp' => '2026-01-07 10:00:02', 'ip' => '192.168.1.3'],
            ['timestamp' => '2026-01-07 10:00:05', 'ip' => '192.168.1.4'],
        ]);

        $qps = $this->analyzer->calculateQPS($logs, 60);

        $this->assertIsFloat($qps);
        $this->assertGreaterThan(0, $qps);
        $this->assertEquals(0.8, $qps); // 4 requests / 5 seconds
    }

    public function test_calculate_qps_with_empty_logs(): void
    {
        $logs = collect([]);

        $qps = $this->analyzer->calculateQPS($logs, 60);

        $this->assertEquals(0.0, $qps);
    }

    public function test_analyze_ip_frequency(): void
    {
        $logs = collect([
            ['ip' => '192.168.1.1'],
            ['ip' => '192.168.1.1'],
            ['ip' => '192.168.1.1'],
            ['ip' => '192.168.1.2'],
            ['ip' => '192.168.1.3'],
        ]);

        $analysis = $this->analyzer->analyzeIPFrequency($logs, 2);

        $this->assertArrayHasKey('top_ips', $analysis);
        $this->assertArrayHasKey('suspicious_ips', $analysis);
        $this->assertArrayHasKey('unique_ips', $analysis);
        $this->assertEquals(3, $analysis['unique_ips']);
        $this->assertEquals(5, $analysis['total_requests']);
        $this->assertArrayHasKey('192.168.1.1', $analysis['suspicious_ips']); // 3 requests > threshold 2
    }

    public function test_analyze_url_patterns(): void
    {
        $logs = collect([
            ['uri' => ['path' => '/api/users'], 'method' => 'GET', 'status' => 200, 'size' => 1024],
            ['uri' => ['path' => '/api/users'], 'method' => 'POST', 'status' => 201, 'size' => 512],
            ['uri' => ['path' => '/api/posts'], 'method' => 'GET', 'status' => 404, 'size' => 256],
            ['uri' => ['path' => '/api/posts'], 'method' => 'GET', 'status' => 200, 'size' => 2048],
        ]);

        $analysis = $this->analyzer->analyzeURLPatterns($logs);

        $this->assertArrayHasKey('top_urls', $analysis);
        $this->assertArrayHasKey('error_urls', $analysis);
        $this->assertArrayHasKey('unique_urls', $analysis);
        $this->assertEquals(2, $analysis['unique_urls']);
        $this->assertArrayHasKey('/api/posts', $analysis['error_urls']); // Has 404 error
    }

    public function test_analyze_user_agents_with_browsers(): void
    {
        $logs = collect([
            ['user_agent' => 'Mozilla/5.0 (Windows NT 10.0) Chrome/90.0'],
            ['user_agent' => 'Mozilla/5.0 (Macintosh) Safari/14.0'],
            ['user_agent' => 'curl/7.68.0'],
            ['user_agent' => 'sqlmap/1.0'],
        ]);

        $analysis = $this->analyzer->analyzeUserAgents($logs);

        $this->assertArrayHasKey('top_user_agents', $analysis);
        $this->assertArrayHasKey('suspicious_agents', $analysis);
        $this->assertArrayHasKey('categories', $analysis);
        
        $this->assertEquals(2, $analysis['categories']['browsers']);
        // curl = 1 tool, sqlmap counted as tool too, but also matched by bot pattern
        $this->assertGreaterThanOrEqual(1, $analysis['categories']['tools']);
        
        // sqlmap should be detected as suspicious
        $this->assertArrayHasKey('sqlmap/1.0', $analysis['suspicious_agents']);
        $this->assertArrayHasKey('curl/7.68.0', $analysis['suspicious_agents']);
    }

    public function test_generate_comprehensive_stats(): void
    {
        $logs = collect([
            [
                'timestamp' => '2026-01-07 10:00:00',
                'ip' => '192.168.1.1',
                'uri' => ['path' => '/api/users'],
                'method' => 'GET',
                'status' => 200,
                'size' => 1024,
                'user_agent' => 'Mozilla/5.0',
            ],
            [
                'timestamp' => '2026-01-07 10:00:02',
                'ip' => '192.168.1.2',
                'uri' => ['path' => '/api/posts'],
                'method' => 'POST',
                'status' => 201,
                'size' => 512,
                'user_agent' => 'Chrome/90.0',
            ],
        ]);

        $stats = $this->analyzer->generateStats($logs);

        $this->assertArrayHasKey('summary', $stats);
        $this->assertArrayHasKey('qps', $stats);
        $this->assertArrayHasKey('http_methods', $stats);
        $this->assertArrayHasKey('status_codes', $stats);
        $this->assertArrayHasKey('ip_analysis', $stats);
        $this->assertArrayHasKey('url_analysis', $stats);
        $this->assertArrayHasKey('user_agent_analysis', $stats);

        $this->assertEquals(2, $stats['summary']['total_requests']);
        $this->assertEquals(2, $stats['summary']['unique_ips']);
        $this->assertEquals(2, $stats['summary']['unique_urls']);
    }

    public function test_track_request_increments_counter(): void
    {
        $ip = '192.168.1.100';

        $count1 = $this->analyzer->trackRequest($ip, 60);
        $count2 = $this->analyzer->trackRequest($ip, 60);
        $count3 = $this->analyzer->trackRequest($ip, 60);

        $this->assertEquals(1, $count1);
        $this->assertEquals(2, $count2);
        $this->assertEquals(3, $count3);
    }

    public function test_build_baseline_from_historical_data(): void
    {
        $logs = collect([
            [
                'timestamp' => '2026-01-07 10:00:00',
                'ip' => '192.168.1.1',
                'uri' => ['path' => '/api/users'],
                'method' => 'GET',
                'status' => 200,
                'size' => 1024,
                'user_agent' => 'Mozilla/5.0',
            ],
            [
                'timestamp' => '2026-01-07 10:00:05',
                'ip' => '192.168.1.1',
                'uri' => ['path' => '/api/posts'],
                'method' => 'GET',
                'status' => 404,
                'size' => 256,
                'user_agent' => 'sqlmap/1.0',
            ],
        ]);

        $baseline = $this->analyzer->buildBaseline($logs);

        $this->assertArrayHasKey('qps', $baseline);
        $this->assertArrayHasKey('avg_requests_per_ip', $baseline);
        $this->assertArrayHasKey('error_rate', $baseline);
        $this->assertArrayHasKey('generated_at', $baseline);

        $this->assertEquals(2, $baseline['avg_requests_per_ip']); // 2 requests / 1 unique IP
        $this->assertEquals(0.5, $baseline['error_rate']); // 1 error / 2 total
    }

    public function test_detect_qps_anomaly(): void
    {
        $currentLogs = collect(array_fill(0, 100, [
            'timestamp' => '2026-01-07 10:00:00',
            'ip' => '192.168.1.1',
            'uri' => ['path' => '/api/test'],
            'method' => 'GET',
            'status' => 200,
            'size' => 100,
            'user_agent' => 'Test',
        ]));

        $baseline = [
            'qps' => ['1min' => 10, '5min' => 8, '15min' => 5],
            'error_rate' => 0.01,
            'user_agent_analysis' => ['suspicious_count' => 0],
        ];

        $anomalies = $this->analyzer->detectAnomalies($currentLogs, $baseline);

        $this->assertNotEmpty($anomalies);
        $this->assertEquals('qps_spike', $anomalies[0]['type']);
        $this->assertEquals('high', $anomalies[0]['severity']);
    }
}
