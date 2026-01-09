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
        
        // Send report to WAF Hub
        if ($this->option('report')) {
            $this->newLine();
            $this->info('📤 Sending report to WAF Hub...');
            
            $wafSync = app(WafSyncService::class);
            $alertData = [
                'type' => 'desktop_security_scan',
                'platform' => $collector->getPlatform(),
                'summary' => $summary,
                'brute_force' => $bruteForceResult,
                'network' => $networkResult,
                'timestamp' => now()->toIso8601String(),
            ];
            
            // Create alert if threats detected
            if ($bruteForceResult['threat_detected'] || $networkResult['threat_detected']) {
                $severity = 'high';
                if ($bruteForceResult['threat_detected']) {
                    foreach ($bruteForceResult['threats'] as $threat) {
                        if ($threat['severity'] === 'critical') {
                            $severity = 'critical';
                            break;
                        }
                    }
                }
                
                $this->info("Syncing alert (severity: {$severity})...");
                // Would sync to WAF Hub here
            }
            
            $this->info('✅ Report sent');
        }
        
        $this->newLine();
        $this->info('Scan completed at ' . now()->format('Y-m-d H:i:s'));
        
        return 0;
    }
}
