<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

/**
 * Desktop AI Analyzer Service
 * 
 * Analyzes desktop system logs using AI to detect security threats
 * such as brute force attacks, suspicious logins, and malicious activity.
 */
class DesktopAiAnalyzer
{
    private string $ollamaUrl;
    private string $ollamaModel;
    private int $timeout;
    private bool $enabled;
    
    public function __construct()
    {
        $this->ollamaUrl = env('OLLAMA_URL', 'https://ollama.futron-life.com');
        $this->ollamaModel = env('OLLAMA_MODEL', 'sentinel-security');
        $this->timeout = (int) env('AI_TIMEOUT', 30);
        $this->enabled = filter_var(env('AI_DETECTION_ENABLED', true), FILTER_VALIDATE_BOOLEAN);
        
        // Override with synced settings from WAF Hub if available
        try {
            $wafSync = app(\App\Services\WafSyncService::class);
            
            // First try the synced config (from heartbeat)
            $syncedConfig = $wafSync->getSyncedConfig();
            
            if (!empty($syncedConfig)) {
                if (isset($syncedConfig['ollama']['url'])) {
                    $this->ollamaUrl = $syncedConfig['ollama']['url'];
                }
                if (isset($syncedConfig['ollama']['model'])) {
                    $this->ollamaModel = $syncedConfig['ollama']['model'];
                }
                if (isset($syncedConfig['ai_detection_enabled'])) {
                    $this->enabled = filter_var($syncedConfig['ai_detection_enabled'], FILTER_VALIDATE_BOOLEAN);
                }
                Log::debug('Using synced Ollama config', [
                    'url' => $this->ollamaUrl,
                    'model' => $this->ollamaModel,
                ]);
            } else {
                // Fallback to cached config if no synced config
                $remoteConfig = $wafSync->getCachedConfig();
                
                if (!empty($remoteConfig)) {
                    if (isset($remoteConfig['ollama']['url'])) {
                        $this->ollamaUrl = $remoteConfig['ollama']['url'];
                    }
                    if (isset($remoteConfig['ollama']['model'])) {
                        $this->ollamaModel = $remoteConfig['ollama']['model'];
                    }
                    if (isset($remoteConfig['ai_detection_enabled'])) {
                        $this->enabled = filter_var($remoteConfig['ai_detection_enabled'], FILTER_VALIDATE_BOOLEAN);
                    } elseif (isset($remoteConfig['log_sync_enabled'])) {
                        $this->enabled = filter_var($remoteConfig['log_sync_enabled'], FILTER_VALIDATE_BOOLEAN);
                    }
                }
            }
        } catch (\Exception $e) {
            Log::debug('Failed to load remote configuration for DesktopAiAnalyzer, using defaults: ' . $e->getMessage());
        }
    }
    
    /**
     * Analyze login attempts for brute force detection
     */
    public function analyzeBruteForce(array $failedLogins): array
    {
        if (!$this->enabled || empty($failedLogins)) {
            return ['threat_detected' => false];
        }
        
        // Group by IP
        $ipGroups = [];
        foreach ($failedLogins as $attempt) {
            $ip = $attempt['ip'] ?? 'unknown';
            $ipGroups[$ip][] = $attempt;
        }
        
        $threats = [];
        foreach ($ipGroups as $ip => $attempts) {
            $count = count($attempts);
            
            // Basic threshold detection
            if ($count >= 5) {
                $threats[] = [
                    'type' => 'brute_force',
                    'ip' => $ip,
                    'attempts' => $count,
                    'severity' => $count >= 20 ? 'critical' : ($count >= 10 ? 'high' : 'medium'),
                    'users_targeted' => array_unique(array_column($attempts, 'user')),
                    'first_attempt' => $attempts[0]['timestamp'] ?? null,
                    'last_attempt' => $attempts[count($attempts) - 1]['timestamp'] ?? null,
                ];
            }
        }
        
        return [
            'threat_detected' => !empty($threats),
            'threats' => $threats,
            'total_failed_attempts' => count($failedLogins),
            'unique_ips' => count($ipGroups),
        ];
    }
    
    /**
     * Analyze login for suspicious patterns using AI
     */
    public function analyzeLoginWithAi(array $loginData): array
    {
        if (!$this->enabled) {
            return ['analyzed' => false, 'reason' => 'AI disabled'];
        }
        
        $cacheKey = 'desktop_ai_login_' . md5(json_encode($loginData));
        if ($cached = Cache::get($cacheKey)) {
            return $cached;
        }
        
        $prompt = $this->buildLoginAnalysisPrompt($loginData);
        
        try {
            $response = Http::timeout($this->timeout)
                ->post("{$this->ollamaUrl}/api/generate", [
                    'model' => $this->ollamaModel,
                    'prompt' => $prompt,
                    'stream' => false,
                    'format' => 'json',
                ]);
            
            if ($response->successful()) {
                $result = $this->parseAiResponse($response->json('response'));
                Cache::put($cacheKey, $result, now()->addMinutes(5));
                return $result;
            }
        } catch (\Exception $e) {
            Log::warning('Desktop AI analysis failed: ' . $e->getMessage());
        }
        
        return ['analyzed' => false, 'error' => 'AI analysis failed'];
    }
    
    /**
     * Analyze network connections for suspicious activity
     */
    public function analyzeNetworkConnections(array $connections): array
    {
        if (!$this->enabled || empty($connections)) {
            return ['threat_detected' => false];
        }
        
        $suspiciousConnections = [];
        $knownBadPorts = [4444, 5555, 6666, 31337, 1337, 12345]; // Common malware ports
        
        foreach ($connections as $conn) {
            $remote = $conn['remote'] ?? '';
            $state = $conn['state'] ?? '';
            
            // Extract port from remote address
            $port = null;
            if (preg_match('/:(\d+)$/', $remote, $matches)) {
                $port = (int) $matches[1];
            }
            
            // Check for suspicious ports
            if ($port && in_array($port, $knownBadPorts)) {
                $suspiciousConnections[] = [
                    'reason' => 'Known malware port',
                    'connection' => $conn,
                    'severity' => 'high',
                ];
            }
            
            // Check for reverse shell patterns (outbound to high ports)
            if ($state === 'ESTABLISHED' && $port && $port > 40000) {
                // Skip common legitimate ports
                if (!in_array($port, [443, 8443, 49152, 49153])) {
                    $suspiciousConnections[] = [
                        'reason' => 'Potential reverse shell (high outbound port)',
                        'connection' => $conn,
                        'severity' => 'medium',
                    ];
                }
            }
        }
        
        return [
            'threat_detected' => !empty($suspiciousConnections),
            'suspicious_connections' => $suspiciousConnections,
            'total_connections' => count($connections),
        ];
    }
    
    /**
     * Perform comprehensive security analysis
     */
    public function analyzeSecurityStatus(array $summary): array
    {
        if (!$this->enabled) {
            return ['analyzed' => false, 'reason' => 'AI disabled'];
        }
        
        $prompt = $this->buildSecuritySummaryPrompt($summary);
        
        try {
            $response = Http::timeout($this->timeout)
                ->post("{$this->ollamaUrl}/api/generate", [
                    'model' => $this->ollamaModel,
                    'prompt' => $prompt,
                    'stream' => false,
                    'format' => 'json',
                ]);
            
            if ($response->successful()) {
                return $this->parseSecurityAnalysis($response->json('response'));
            }
        } catch (\Exception $e) {
            Log::warning('Desktop security analysis failed: ' . $e->getMessage());
        }
        
        return ['analyzed' => false, 'error' => 'Analysis failed'];
    }
    
    /**
     * Analyze enhanced system logs (system, app, firewall, security audit)
     */
    public function analyzeEnhancedLogs(array $allLogs): array
    {
        if (!$this->enabled) {
            return ['analyzed' => false, 'reason' => 'AI disabled'];
        }
        
        // Prepare log summary for AI
        $logSummary = [
            'system_logs' => $this->summarizeLogs($allLogs['system'] ?? [], 'system'),
            'application_logs' => $this->summarizeLogs($allLogs['applications'] ?? [], 'application'),
            'firewall_logs' => $this->summarizeLogs($allLogs['firewall'] ?? [], 'firewall'),
            'security_audit_logs' => $this->summarizeLogs($allLogs['security_audit'] ?? [], 'security'),
            'auth_logs' => $this->summarizeLogs($allLogs['auth'] ?? [], 'auth'),
        ];
        
        // Check for immediate threats in firewall logs
        $firewallThreats = $this->detectFirewallThreats($allLogs['firewall'] ?? []);
        
        // Check for security violations
        $securityViolations = $this->detectSecurityViolations($allLogs['security_audit'] ?? []);
        
        // Check for app crashes (potential exploitation)
        $appCrashes = $this->detectAppCrashes($allLogs['applications'] ?? []);
        
        // Build comprehensive analysis
        $threats = array_merge($firewallThreats, $securityViolations, $appCrashes);
        
        // Use AI for deeper analysis if we have any logs
        $totalLogs = array_sum(array_map('count', $allLogs));
        $aiAnalysis = null;
        
        // Always perform AI analysis if there are logs (removed threshold)
        if ($totalLogs > 0) {
            Log::info("Performing AI log analysis on {$totalLogs} logs using {$this->ollamaUrl}");
            $aiAnalysis = $this->performAiLogAnalysis($logSummary);
        }
        
        return [
            'analyzed' => true,
            'threat_detected' => !empty($threats),
            'threats' => $threats,
            'summary' => $logSummary,
            'total_logs_analyzed' => $totalLogs,
            'ai_analysis' => $aiAnalysis,
        ];
    }
    
    /**
     * Summarize logs for AI analysis
     */
    private function summarizeLogs(array $logs, string $category): array
    {
        if (empty($logs)) {
            return ['count' => 0, 'types' => [], 'sample' => null];
        }
        
        $types = [];
        $errorCount = 0;
        
        foreach ($logs as $log) {
            $type = $log['type'] ?? $log['level'] ?? 'unknown';
            $types[$type] = ($types[$type] ?? 0) + 1;
            
            if (in_array(strtolower($log['level'] ?? ''), ['error', 'fault', 'critical'])) {
                $errorCount++;
            }
        }
        
        return [
            'count' => count($logs),
            'types' => $types,
            'error_count' => $errorCount,
            'sample' => isset($logs[0]) ? substr($logs[0]['raw'] ?? '', 0, 200) : null,
        ];
    }
    
    /**
     * Detect threats from firewall logs
     */
    private function detectFirewallThreats(array $firewallLogs): array
    {
        $threats = [];
        $blockedIps = [];
        
        foreach ($firewallLogs as $log) {
            $raw = strtolower($log['raw'] ?? '');
            
            // Look for blocked/denied connections
            if (preg_match('/(block|deny|reject|drop)/i', $raw)) {
                $ip = $log['ip'] ?? null;
                if ($ip && $ip !== 'unknown') {
                    $blockedIps[$ip] = ($blockedIps[$ip] ?? 0) + 1;
                }
            }
        }
        
        // Flag IPs with multiple blocked attempts
        foreach ($blockedIps as $ip => $count) {
            if ($count >= 5) {
                $threats[] = [
                    'type' => 'firewall_block',
                    'source' => 'firewall',
                    'ip' => $ip,
                    'blocked_count' => $count,
                    'severity' => $count >= 20 ? 'high' : 'medium',
                    'description' => "IP {$ip} was blocked {$count} times by firewall",
                ];
            }
        }
        
        return $threats;
    }
    
    /**
     * Detect security violations from security audit logs
     */
    private function detectSecurityViolations(array $securityLogs): array
    {
        $threats = [];
        
        foreach ($securityLogs as $log) {
            $raw = strtolower($log['raw'] ?? '');
            
            // Look for keychain access violations
            if (preg_match('/(keychain|credential).*?(denied|failed|error)/i', $raw)) {
                $threats[] = [
                    'type' => 'credential_access_violation',
                    'source' => 'security_audit',
                    'severity' => 'medium',
                    'description' => 'Credential or keychain access violation detected',
                    'raw' => substr($log['raw'] ?? '', 0, 200),
                ];
            }
            
            // Look for code signing violations
            if (preg_match('/codesign.*(invalid|failed|untrusted)/i', $raw)) {
                $threats[] = [
                    'type' => 'code_signature_violation',
                    'source' => 'security_audit',
                    'severity' => 'high',
                    'description' => 'Code signature validation failed - potential malware',
                    'raw' => substr($log['raw'] ?? '', 0, 200),
                ];
            }
        }
        
        return array_slice($threats, 0, 10); // Limit to prevent flooding
    }
    
    /**
     * Detect app crashes that might indicate exploitation
     */
    private function detectAppCrashes(array $appLogs): array
    {
        $threats = [];
        $crashCounts = [];
        
        foreach ($appLogs as $log) {
            $raw = strtolower($log['raw'] ?? '');
            $process = $log['process'] ?? 'unknown';
            
            // Look for crash patterns
            if (preg_match('/(crash|exception|fault|segmentation|abort)/i', $raw)) {
                $crashCounts[$process] = ($crashCounts[$process] ?? 0) + 1;
            }
        }
        
        // Multiple crashes of same app could indicate exploitation
        foreach ($crashCounts as $process => $count) {
            if ($count >= 3) {
                $threats[] = [
                    'type' => 'repeated_crash',
                    'source' => 'application',
                    'process' => $process,
                    'crash_count' => $count,
                    'severity' => $count >= 10 ? 'high' : 'medium',
                    'description' => "Process {$process} crashed {$count} times - potential exploitation attempt",
                ];
            }
        }
        
        return $threats;
    }
    
    /**
     * Perform AI analysis on log summary
     */
    private function performAiLogAnalysis(array $logSummary): ?array
    {
        $prompt = $this->buildEnhancedLogAnalysisPrompt($logSummary);
        
        try {
            $response = Http::timeout($this->timeout)
                ->post("{$this->ollamaUrl}/api/generate", [
                    'model' => $this->ollamaModel,
                    'prompt' => $prompt,
                    'stream' => false,
                    'format' => 'json',
                ]);
            
            if ($response->successful()) {
                $data = json_decode($response->json('response'), true);
                if (is_array($data)) {
                    return $data;
                }
            }
        } catch (\Exception $e) {
            Log::warning('Enhanced log AI analysis failed: ' . $e->getMessage());
        }
        
        return null;
    }
    
    /**
     * Build prompt for enhanced log analysis
     */
    private function buildEnhancedLogAnalysisPrompt(array $logSummary): string
    {
        $json = json_encode($logSummary, JSON_PRETTY_PRINT);
        
        return <<<PROMPT
You are a security analyst reviewing comprehensive system logs from a personal computer.

Log Summary:
{$json}

Analyze these logs for:
1. Security threats (malware, intrusion attempts, unauthorized access)
2. System stability issues that could indicate compromise
3. Suspicious application behavior
4. Firewall activity anomalies
5. Authentication and access patterns

Respond in JSON format:
{
    "threat_level": "none|low|medium|high|critical",
    "confidence": 0-100,
    "findings": [
        {"category": "string", "severity": "low|medium|high", "description": "string"}
    ],
    "recommendations": ["action1", "action2"],
    "summary": "brief security assessment"
}
PROMPT;
    }
    
    /**
     * Build prompt for login analysis
     */
    private function buildLoginAnalysisPrompt(array $loginData): string
    {
        $json = json_encode($loginData, JSON_PRETTY_PRINT);
        
        return <<<PROMPT
You are a security analyst for a personal computer IDS system.
Analyze this login event data and determine if it's suspicious:

{$json}

Consider:
1. Is this login from an unusual IP or location?
2. Is the login at an unusual time?
3. Are there any signs of automated/scripted access?
4. Is the user account typically used for this type of access?

Respond in JSON format:
{
    "suspicious": true/false,
    "threat_level": "none|low|medium|high|critical",
    "threat_type": "string or null",
    "reason": "explanation",
    "recommended_action": "string"
}
PROMPT;
    }
    
    /**
     * Build prompt for security summary analysis
     */
    private function buildSecuritySummaryPrompt(array $summary): string
    {
        $json = json_encode($summary, JSON_PRETTY_PRINT);
        
        return <<<PROMPT
You are a security analyst reviewing a personal computer's 24-hour security summary.

Security Summary:
{$json}

Analyze this data and provide:
1. Overall threat assessment
2. Key concerns
3. Recommended actions

Respond in JSON format:
{
    "overall_risk": "low|medium|high|critical",
    "threat_score": 0-100,
    "key_findings": ["finding1", "finding2"],
    "recommendations": ["action1", "action2"],
    "summary": "brief text summary"
}
PROMPT;
    }
    
    /**
     * Parse AI response for login analysis
     */
    private function parseAiResponse(string $response): array
    {
        try {
            $data = json_decode($response, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return [
                    'analyzed' => true,
                    'suspicious' => $data['suspicious'] ?? false,
                    'threat_level' => $data['threat_level'] ?? 'none',
                    'threat_type' => $data['threat_type'] ?? null,
                    'reason' => $data['reason'] ?? null,
                    'recommended_action' => $data['recommended_action'] ?? null,
                ];
            }
        } catch (\Exception $e) {
            Log::warning('Failed to parse AI response: ' . $e->getMessage());
        }
        
        return ['analyzed' => false, 'error' => 'Failed to parse response'];
    }
    
    /**
     * Parse security analysis response
     */
    private function parseSecurityAnalysis(string $response): array
    {
        try {
            $data = json_decode($response, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return [
                    'analyzed' => true,
                    'overall_risk' => $data['overall_risk'] ?? 'low',
                    'threat_score' => $data['threat_score'] ?? 0,
                    'key_findings' => $data['key_findings'] ?? [],
                    'recommendations' => $data['recommendations'] ?? [],
                    'summary' => $data['summary'] ?? null,
                ];
            }
        } catch (\Exception $e) {
            Log::warning('Failed to parse security analysis: ' . $e->getMessage());
        }
        
        return ['analyzed' => false, 'error' => 'Failed to parse response'];
    }
}
