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
