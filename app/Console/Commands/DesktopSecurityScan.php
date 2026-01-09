<?php

namespace App\Console\Commands;

use App\Services\DesktopLogCollector;
use App\Services\DesktopAiAnalyzer;
use App\Services\WafSyncService;
use Illuminate\Console\Command;

class DesktopSecurityScan extends Command
{
    protected $signature = 'desktop:scan 
                            {--full : Perform full AI analysis}
                            {--report : Generate and send report to WAF Hub}';
    
    protected $description = 'Scan desktop system for security threats';

    public function handle(): int
    {
        $this->info('🖥️  Desktop Security Scan');
        $this->info('=' . str_repeat('=', 50));
        
        $collector = new DesktopLogCollector();
        $analyzer = new DesktopAiAnalyzer();
        
        $this->info("Platform: {$collector->getPlatform()}");
        $this->newLine();
        
        // Debug: Test raw log collection
        if ($this->output->isVerbose() || $this->output->isVeryVerbose()) {
            $this->warn('🔧 DEBUG: Testing raw log collection...');
            $authLogs = $collector->collectAuthLogs(200);
            $this->info("  Auth logs collected: " . count($authLogs));
            
            // Count by type
            $typeCounts = [];
            $samples = ['failed_login' => [], 'successful_login' => [], 'unknown' => []];
            foreach ($authLogs as $log) {
                $type = $log['type'] ?? 'null';
                $typeCounts[$type] = ($typeCounts[$type] ?? 0) + 1;
                if (count($samples[$type] ?? []) < 2) {
                    $samples[$type][] = substr($log['raw'] ?? '', 0, 100);
                }
            }
            
            $this->info("  Type breakdown:");
            foreach ($typeCounts as $type => $count) {
                $this->line("    - {$type}: {$count}");
            }
            
            // Show samples of unknown logs to understand format
            if (!empty($samples['unknown'])) {
                $this->warn("  Sample unknown logs (to debug parsing):");
                foreach (array_slice($samples['unknown'], 0, 3) as $sample) {
                    $this->line("    > " . $sample);
                }
            }
            
            // Show samples of successful_login to verify correctness
            if (!empty($samples['successful_login'])) {
                $this->info("  Sample successful_login logs:");
                foreach (array_slice($samples['successful_login'], 0, 3) as $sample) {
                    $this->line("    > " . $sample);
                }
            }
            
            // Show samples of failed_login to verify correctness
            if (!empty($samples['failed_login'])) {
                $this->warn("  Sample failed_login logs:");
                foreach (array_slice($samples['failed_login'], 0, 3) as $sample) {
                    $this->line("    > " . $sample);
                }
            }
        }
        
        // Collect security summary
        $this->info('📊 Collecting security data...');
        $summary = $collector->getSecuritySummary();
        
        $this->table(
            ['Metric', 'Value'],
            [
                ['Failed Logins (24h)', $summary['failed_logins_24h']],
                ['Successful Logins (24h)', $summary['successful_logins_24h']],
                ['Total Connections', $summary['total_connections']],
                ['External Connections', $summary['external_connections']],
            ]
        );
        
        // Show top failed IPs
        if (!empty($summary['top_failed_ips'])) {
            $this->newLine();
            $this->info('🚨 Top Failed Login IPs:');
            foreach ($summary['top_failed_ips'] as $ip => $count) {
                $this->warn("   {$ip}: {$count} attempts");
            }
        }
        
        // Brute force detection
        $this->newLine();
        $this->info('🔍 Analyzing for brute force attacks...');
        $failedLogins = $collector->getFailedLogins(24);
        $bruteForceResult = $analyzer->analyzeBruteForce($failedLogins);
        
        if ($bruteForceResult['threat_detected']) {
            $this->error('⚠️  BRUTE FORCE ATTACK DETECTED!');
            foreach ($bruteForceResult['threats'] as $threat) {
                $this->warn("   IP: {$threat['ip']} - {$threat['attempts']} attempts - Severity: {$threat['severity']}");
            }
        } else {
            $this->info('✅ No brute force attacks detected');
        }
        
        // Network analysis
        $this->newLine();
        $this->info('🌐 Analyzing network connections...');
        $connections = $collector->collectNetworkConnections();
        $networkResult = $analyzer->analyzeNetworkConnections($connections);
        
        if ($networkResult['threat_detected']) {
            $this->error('⚠️  SUSPICIOUS NETWORK ACTIVITY DETECTED!');
            foreach ($networkResult['suspicious_connections'] as $suspicious) {
                $this->warn("   {$suspicious['reason']} - {$suspicious['connection']['remote']}");
            }
        } else {
            $this->info('✅ No suspicious network activity');
        }
        
        // Full AI analysis
        if ($this->option('full')) {
            $this->newLine();
            $this->info('🤖 Performing AI security analysis...');
            $aiResult = $analyzer->analyzeSecurityStatus($summary);
            
            if ($aiResult['analyzed']) {
                $this->newLine();
                $this->info("Overall Risk: {$aiResult['overall_risk']}");
                $this->info("Threat Score: {$aiResult['threat_score']}/100");
                
                if (!empty($aiResult['key_findings'])) {
                    $this->warn('Key Findings:');
                    foreach ($aiResult['key_findings'] as $finding) {
                        $this->line("   • {$finding}");
                    }
                }
                
                if (!empty($aiResult['recommendations'])) {
                    $this->info('Recommendations:');
                    foreach ($aiResult['recommendations'] as $rec) {
                        $this->line("   → {$rec}");
                    }
                }
            } else {
                $this->warn('AI analysis unavailable');
            }
        }
        
        // Always send heartbeat and sync summary to WAF Hub
        $wafSync = app(WafSyncService::class);
        
        // Send heartbeat to keep agent alive
        $this->info('💓 Sending heartbeat to WAF Hub...');
        $heartbeatOk = $wafSync->heartbeat();
        if ($heartbeatOk) {
            $this->info('✅ Heartbeat sent');
        } else {
            $this->warn('⚠️  Heartbeat failed - check WAF_URL and AGENT_TOKEN');
        }
        
        // Send report to WAF Hub (always sync if threats detected, or if --report flag)
        $shouldReport = $this->option('report') || $bruteForceResult['threat_detected'] || $networkResult['threat_detected'];
        
        if ($shouldReport) {
            $this->newLine();
            $this->info('📤 Sending report to WAF Hub...');
            
            $alertsSent = 0;
            
            // Send individual alerts for each brute force threat
            if ($bruteForceResult['threat_detected']) {
                foreach ($bruteForceResult['threats'] ?? [] as $threat) {
                    $alertData = [
                        'source_ip' => $threat['ip'] ?? '0.0.0.0',
                        'severity' => $threat['severity'] ?? 'high',
                        'category' => 'brute_force',
                        'log_type' => 'system',
                        'detections' => "Brute force attack: {$threat['attempts']} failed login attempts",
                        'raw_log' => json_encode([
                            'platform' => $collector->getPlatform(),
                            'attempts' => $threat['attempts'] ?? 0,
                            'timestamp' => now()->toIso8601String(),
                        ]),
                    ];
                    
                    $response = $wafSync->syncAlert($alertData);
                    if ($response && $response->successful()) {
                        $alertsSent++;
                        if ($this->option('verbose')) {
                            $this->info("   ✅ Alert synced: " . substr($response->body(), 0, 100));
                        }
                    } else if ($response) {
                        $this->warn("   Alert sync failed: HTTP {$response->status()} - " . substr($response->body(), 0, 200));
                    } else {
                        $this->warn("   Alert sync failed: No response");
                    }
                }
            }
            
            // Send network threat alerts
            if ($networkResult['threat_detected']) {
                foreach ($networkResult['suspicious_connections'] ?? [] as $suspicious) {
                    $conn = $suspicious['connection'] ?? [];
                    $alertData = [
                        'source_ip' => $conn['remote'] ?? $conn['remote_ip'] ?? '0.0.0.0',
                        'severity' => 'medium',
                        'category' => 'suspicious_network',
                        'log_type' => 'system',
                        'detections' => $suspicious['reason'] ?? 'Suspicious network activity',
                        'raw_log' => json_encode([
                            'platform' => $collector->getPlatform(),
                            'connection' => $conn,
                            'timestamp' => now()->toIso8601String(),
                        ]),
                    ];
                    
                    $response = $wafSync->syncAlert($alertData);
                    if ($response && $response->successful()) {
                        $alertsSent++;
                    }
                }
            }
            
            if ($alertsSent > 0) {
                $this->info("✅ {$alertsSent} alert(s) sent");
            } else {
                $this->warn('⚠️  No alerts sent (no valid threats or sync failed)');
            }
        }
        
        $this->newLine();
        $this->info('Scan completed at ' . now()->format('Y-m-d H:i:s'));
        
        return 0;
    }
}
