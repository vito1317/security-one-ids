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
        
        // Initialize enhanced analysis variable at function scope for later sync
        $macEnhancedAnalysis = null;
        
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
            
            // macOS Enhanced Log Collection
            if ($collector->getPlatform() === 'macos') {
                $this->newLine();
                $this->info('📋 macOS Enhanced Log Collection:');
                
                // Collect all macOS enhanced logs
                $systemLogs = $collector->collectMacOsSystemLogs(60);
                $this->line("  📦 System logs: " . count($systemLogs));
                
                $appLogs = $collector->collectMacOsAppLogs(60);
                $this->line("  📱 Application logs: " . count($appLogs));
                
                $firewallLogs = $collector->collectMacOsFirewallLogs(60);
                $this->line("  🔥 Firewall logs: " . count($firewallLogs));
                
                $securityLogs = $collector->collectMacOsSecurityAuditLogs(60);
                $this->line("  🔐 Security audit logs: " . count($securityLogs));
                
                // Store for AI analysis
                $enhancedLogs = [
                    'auth' => $authLogs,
                    'system' => $systemLogs,
                    'applications' => $appLogs,
                    'firewall' => $firewallLogs,
                    'security_audit' => $securityLogs,
                ];
                
                // Perform AI analysis on enhanced logs
                $enhancedAnalysis = null;
                if ($this->option('full')) {
                    $this->newLine();
                    $this->info('🤖 Analyzing enhanced logs with AI...');
                    $enhancedAnalysis = $analyzer->analyzeEnhancedLogs($enhancedLogs);
                    
                    if ($enhancedAnalysis['analyzed']) {
                        $this->line("  📊 Total logs analyzed: " . $enhancedAnalysis['total_logs_analyzed']);
                        
                        // Display threats detected
                        if (!empty($enhancedAnalysis['threats'])) {
                            $this->newLine();
                            $this->error('  ⚠️ THREATS DETECTED FROM ENHANCED LOGS:');
                            foreach ($enhancedAnalysis['threats'] as $threat) {
                                $severity = strtoupper($threat['severity'] ?? 'unknown');
                                $this->warn("    [{$severity}] {$threat['type']}: {$threat['description']}");
                            }
                        } else {
                            $this->info('  ✅ No immediate threats detected in enhanced logs');
                        }
                        
                        // Display AI analysis if available
                        if (!empty($enhancedAnalysis['ai_analysis'])) {
                            $ai = $enhancedAnalysis['ai_analysis'];
                            $this->newLine();
                            $this->info('  🧠 AI Security Assessment:');
                            $this->line("    Threat Level: " . ($ai['threat_level'] ?? 'unknown'));
                            $this->line("    Confidence: " . ($ai['confidence'] ?? 0) . "%");
                            
                            if (!empty($ai['findings'])) {
                                $this->line("    Findings:");
                                foreach (array_slice($ai['findings'], 0, 5) as $finding) {
                                    $this->line("      • [{$finding['severity']}] {$finding['description']}");
                                }
                            }
                            
                            if (!empty($ai['recommendations'])) {
                                $this->line("    Recommendations:");
                                foreach (array_slice($ai['recommendations'], 0, 3) as $rec) {
                                    $this->line("      → {$rec}");
                                }
                            }
                        }
                    }
                }
                
                // Store for later sync
                $macEnhancedAnalysis = $enhancedAnalysis;
                
                // Show samples if in very verbose mode
                if ($this->output->isVeryVerbose()) {
                    if (!empty($systemLogs)) {
                        $this->info("  Sample system log:");
                        $this->line("    > " . substr($systemLogs[0]['raw'] ?? '', 0, 150));
                    }
                    if (!empty($appLogs)) {
                        $this->info("  Sample app log:");
                        $this->line("    > " . substr($appLogs[0]['raw'] ?? '', 0, 150));
                    }
                    if (!empty($firewallLogs)) {
                        $this->warn("  Sample firewall log:");
                        $this->line("    > " . substr($firewallLogs[0]['raw'] ?? '', 0, 150));
                    }
                    if (!empty($securityLogs)) {
                        $this->info("  Sample security log:");
                        $this->line("    > " . substr($securityLogs[0]['raw'] ?? '', 0, 150));
                    }
                }
            }
            
            // Windows Enhanced Log Collection
            if ($collector->getPlatform() === 'windows') {
                $this->newLine();
                $this->info('📋 Windows Enhanced Log Collection:');
                
                // Collect Windows event logs
                $securityLogs = $collector->collectWindowsEventLog('Security', 100);
                $this->line("  🔐 Security logs: " . count($securityLogs));
                
                $systemLogs = $collector->collectWindowsEventLog('System', 50);
                $this->line("  📦 System logs: " . count($systemLogs));
                
                $appLogs = $collector->collectWindowsEventLog('Application', 50);
                $this->line("  📱 Application logs: " . count($appLogs));
                
                // Store for AI analysis
                $enhancedLogs = [
                    'auth' => $authLogs,
                    'security' => $securityLogs,
                    'system' => $systemLogs,
                    'applications' => $appLogs,
                ];
                
                // Perform AI analysis on enhanced logs
                $enhancedAnalysis = null;
                if ($this->option('full')) {
                    $this->newLine();
                    $this->info('🤖 Analyzing enhanced logs with AI...');
                    $enhancedAnalysis = $analyzer->analyzeEnhancedLogs($enhancedLogs);
                    
                    if ($enhancedAnalysis['analyzed']) {
                        $this->line("  📊 Total logs analyzed: " . $enhancedAnalysis['total_logs_analyzed']);
                        
                        // Display threats detected
                        if (!empty($enhancedAnalysis['threats'])) {
                            $this->newLine();
                            $this->error('  ⚠️ THREATS DETECTED FROM ENHANCED LOGS:');
                            foreach ($enhancedAnalysis['threats'] as $threat) {
                                $severity = strtoupper($threat['severity'] ?? 'unknown');
                                $this->warn("    [{$severity}] {$threat['type']}: {$threat['description']}");
                            }
                        } else {
                            $this->info('  ✅ No immediate threats detected in enhanced logs');
                        }
                        
                        // Display AI analysis if available
                        if (!empty($enhancedAnalysis['ai_analysis'])) {
                            $ai = $enhancedAnalysis['ai_analysis'];
                            $this->newLine();
                            $this->info('  🧠 AI Security Assessment:');
                            $this->line("    Threat Level: " . ($ai['threat_level'] ?? 'unknown'));
                            $this->line("    Confidence: " . ($ai['confidence'] ?? 0) . "%");
                            
                            if (!empty($ai['findings'])) {
                                $this->line("    Findings:");
                                foreach (array_slice($ai['findings'], 0, 5) as $finding) {
                                    $this->line("      • [{$finding['severity']}] {$finding['description']}");
                                }
                            }
                            
                            if (!empty($ai['recommendations'])) {
                                $this->line("    Recommendations:");
                                foreach (array_slice($ai['recommendations'], 0, 3) as $rec) {
                                    $this->line("      → {$rec}");
                                }
                            }
                        }
                    }
                }
                
                // Store for later sync (Windows uses same variable name)
                $macEnhancedAnalysis = $enhancedAnalysis;
                
                // Show samples if in very verbose mode
                if ($this->output->isVeryVerbose()) {
                    if (!empty($securityLogs)) {
                        $this->info("  Sample security log:");
                        $this->line("    > " . substr($securityLogs[0]['raw'] ?? '', 0, 150));
                    }
                    if (!empty($systemLogs)) {
                        $this->info("  Sample system log:");
                        $this->line("    > " . substr($systemLogs[0]['raw'] ?? '', 0, 150));
                    }
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
        
        // Check if we have enhanced log threats to report
        $hasEnhancedThreats = !empty($macEnhancedAnalysis['threats']);
        
        // DEBUG: Trace sync condition
        $this->warn("DEBUG SYNC: macEnhancedAnalysis is " . ($macEnhancedAnalysis === null ? 'NULL' : 'SET'));
        $this->warn("DEBUG SYNC: hasEnhancedThreats = " . ($hasEnhancedThreats ? 'TRUE' : 'FALSE'));
        if ($macEnhancedAnalysis !== null && isset($macEnhancedAnalysis['threats'])) {
            $this->warn("DEBUG SYNC: threats array count = " . count($macEnhancedAnalysis['threats']));
        }
        
        // Send report to WAF Hub (always sync if threats detected, or if --report flag)
        $shouldReport = $this->option('report') || $bruteForceResult['threat_detected'] || $networkResult['threat_detected'] || $hasEnhancedThreats;
        $this->warn("DEBUG SYNC: shouldReport = " . ($shouldReport ? 'TRUE' : 'FALSE'));
        
        if ($shouldReport) {
            $this->newLine();
            $this->info('📤 Sending report to WAF Hub...');
            
            $alertsSent = 0;
            
            // Send individual alerts for each brute force threat
            if ($bruteForceResult['threat_detected']) {
                foreach ($bruteForceResult['threats'] ?? [] as $threat) {
                    // Validate IP address - use 127.0.0.1 for local/unknown IPs
                    $sourceIp = $threat['ip'] ?? null;
                    if (!$sourceIp || $sourceIp === 'unknown' || !filter_var($sourceIp, FILTER_VALIDATE_IP)) {
                        $sourceIp = '127.0.0.1'; // Local attack (e.g., su/sudo failures)
                    }
                    
                    $alertData = [
                        'source_ip' => $sourceIp,
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
                    // Validate IP address
                    $sourceIp = $conn['remote'] ?? $conn['remote_ip'] ?? null;
                    if (!$sourceIp || $sourceIp === 'unknown' || !filter_var($sourceIp, FILTER_VALIDATE_IP)) {
                        $sourceIp = '127.0.0.1';
                    }
                    
                    $alertData = [
                        'source_ip' => $sourceIp,
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
            
            // Send enhanced log threats (from macOS or Windows analysis)
            $enhancedAnalysisToSync = $macEnhancedAnalysis ?? null;
            
            if ($enhancedAnalysisToSync && !empty($enhancedAnalysisToSync['threats'])) {
                $this->info('📤 Sending enhanced log threats...');
                foreach ($enhancedAnalysisToSync['threats'] as $threat) {
                    $sourceIp = $threat['ip'] ?? '127.0.0.1';
                    if (!filter_var($sourceIp, FILTER_VALIDATE_IP)) {
                        $sourceIp = '127.0.0.1';
                    }
                    
                    $alertData = [
                        'source_ip' => $sourceIp,
                        'severity' => $threat['severity'] ?? 'medium',
                        'category' => $threat['type'] ?? 'enhanced_log_threat',
                        'log_type' => $threat['source'] ?? 'system',
                        'detections' => $threat['description'] ?? 'Enhanced log threat detected',
                        'raw_log' => json_encode([
                            'platform' => $collector->getPlatform(),
                            'threat_type' => $threat['type'],
                            'details' => array_diff_key($threat, array_flip(['description', 'type', 'severity', 'source', 'ip'])),
                            'timestamp' => now()->toIso8601String(),
                        ]),
                    ];
                    
                    $response = $wafSync->syncAlert($alertData);
                    if ($response && $response->successful()) {
                        $alertsSent++;
                        if ($this->option('verbose')) {
                            $this->info("   ✅ Enhanced threat synced: {$threat['type']}");
                        }
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
