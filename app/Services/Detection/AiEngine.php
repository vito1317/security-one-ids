<?php

namespace App\Services\Detection;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * AI Detection Engine
 * 
 * Uses Ollama API for intelligent threat detection
 */
class AiEngine
{
    private string $ollamaUrl;
    private string $ollamaModel;
    private string $sensitivity;
    private bool $enabled;
    private int $timeout;

    public function __construct()
    {
        // First load from environment
        $this->ollamaUrl = env('OLLAMA_URL', 'https://ollama.futron-life.com');
        $this->ollamaModel = env('OLLAMA_MODEL', 'sentinel-security');
        $this->sensitivity = env('AI_SENSITIVITY', 'medium');
        $this->timeout = (int) env('AI_TIMEOUT', 15);
        $this->enabled = filter_var(env('AI_DETECTION_ENABLED', false), FILTER_VALIDATE_BOOLEAN);
        
        // Override with synced settings from WAF Hub if available
        try {
            $wafSync = app(\App\Services\WafSyncService::class);
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
                    // Fallback to log_sync_enabled if specifically not set
                    $this->enabled = filter_var($remoteConfig['log_sync_enabled'], FILTER_VALIDATE_BOOLEAN);
                }
            }
        } catch (\Exception $e) {
            Log::debug('Failed to load remote configuration for AiEngine, using defaults: ' . $e->getMessage());
        }
    }

    /**
     * Analyze log data using AI
     *
     * @param array $logData Parsed log entry
     * @return array|null Detection result or null if no threat
     */
    public function analyze(array $logData): ?array
    {
        if (!$this->enabled) {
            return null;
        }

        try {
            // Build request string for analysis
            $requestString = $this->buildRequestString($logData);
            
            // Skip very short requests
            if (strlen($requestString) < 10) {
                return null;
            }

            // Skip whitelisted paths
            $uri = $logData['uri']['path'] ?? '';
            if ($this->isWhitelistedPath($uri)) {
                return null;
            }

            // Check cache to avoid analyzing same pattern repeatedly
            $cacheKey = 'ai_detection:' . md5($requestString);
            if ($cached = Cache::get($cacheKey)) {
                return $cached === 'safe' ? null : $cached;
            }

            // Call Ollama API
            $result = $this->callOllamaApi($requestString);
            
            if ($result === null) {
                // API error, fail open
                return null;
            }

            // Cache result for 5 minutes
            Cache::put($cacheKey, $result ?: 'safe', 300);

            if ($result) {
                Log::warning('AI detected threat', [
                    'ip' => $logData['ip'] ?? 'unknown',
                    'uri' => $uri,
                    'threat_type' => $result['threat_type'] ?? 'unknown',
                    'score' => $result['score'] ?? 0,
                ]);
            }

            return $result;
        } catch (\Exception $e) {
            Log::error('AI detection error: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Build request string for AI analysis
     */
    private function buildRequestString(array $logData): string
    {
        $parts = [];
        
        // Method
        if (isset($logData['method'])) {
            $parts[] = "Method: " . $logData['method'];
        }
        
        // URI
        if (isset($logData['uri'])) {
            $uri = $logData['uri']['full'] ?? $logData['uri']['path'] ?? '';
            $parts[] = "URI: " . $uri;
        }
        
        // Query parameters
        if (!empty($logData['uri']['query_string'])) {
            $parts[] = "Query: " . $logData['uri']['query_string'];
        }
        
        // User Agent
        if (!empty($logData['user_agent'])) {
            $parts[] = "User-Agent: " . $logData['user_agent'];
        }
        
        return implode("\n", $parts);
    }

    /**
     * Path whitelist to skip AI analysis
     */
    private function isWhitelistedPath(string $path): bool
    {
        $whitelist = [
            '/health',
            '/ping',
            '/favicon.ico',
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/',
        ];

        foreach ($whitelist as $pattern) {
            if (str_starts_with($path, $pattern) || str_contains($path, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Call Ollama API for threat detection
     */
    private function callOllamaApi(string $requestString): ?array
    {
        try {
            $prompt = $this->buildPrompt($requestString);
            
            $response = Http::timeout($this->timeout)
                ->post(rtrim($this->ollamaUrl, '/') . '/api/generate', [
                    'model' => $this->ollamaModel,
                    'prompt' => $prompt,
                    'stream' => false,
                    'options' => [
                        'num_predict' => 100,
                        'temperature' => 0.1,
                    ],
                ]);

            if (!$response->successful()) {
                Log::warning('Ollama API error', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);
                return null;
            }

            $data = $response->json();
            $aiResponse = trim($data['response'] ?? '');
            
            Log::debug('AI Response', ['response' => $aiResponse]);

            return $this->parseAiResponse($aiResponse);
        } catch (\Exception $e) {
            Log::error('Ollama API call failed: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Build prompt for AI analysis
     */
    private function buildPrompt(string $requestString): string
    {
        $sensitivityGuide = match ($this->sensitivity) {
            'low' => 'Only detect OBVIOUS attacks like SQL injection syntax or shell commands.',
            'high' => 'Detect any suspicious patterns including obfuscated attacks.',
            default => 'Detect clear attack patterns but allow normal application traffic.',
        };

        return <<<PROMPT
You are a security analyzer for an IDS system. Analyze the following HTTP request for malicious patterns.

Rules:
1. Normal URLs like /app/dashboard, /api/users are SAFE
2. Query parameters like ?id=123&name=test are SAFE
3. Only flag CLEAR attack patterns:
   - SQL Injection: UNION SELECT, OR 1=1, DROP TABLE, ' OR '
   - XSS: <script>, javascript:, onerror=
   - RCE: system(, exec(, /etc/passwd
   - Path Traversal: ../, ....//

Sensitivity: {$sensitivityGuide}

Request:
{$requestString}

Respond ONLY in JSON format:
{"threat": true/false, "type": "attack_type", "score": 0-100, "reason": "brief explanation"}

If safe, respond: {"threat": false}
PROMPT;
    }

    /**
     * Parse AI response into detection result
     */
    private function parseAiResponse(string $response): ?array
    {
        // Try to extract JSON from response
        if (preg_match('/\{[^}]+\}/', $response, $matches)) {
            $json = json_decode($matches[0], true);
            
            if (json_last_error() === JSON_ERROR_NONE) {
                $isThreat = filter_var($json['threat'] ?? false, FILTER_VALIDATE_BOOLEAN);
                
                if (!$isThreat) {
                    return null;
                }

                $score = (int) ($json['score'] ?? 50);
                $type = $json['type'] ?? 'ai_detected';
                $reason = $json['reason'] ?? 'AI detected potential threat';

                // Determine severity from score
                $severity = match (true) {
                    $score >= 80 => 'critical',
                    $score >= 60 => 'high',
                    $score >= 40 => 'medium',
                    default => 'low',
                };

                return [
                    'detected' => true,
                    'threat_type' => $type,
                    'score' => $score,
                    'severity' => $severity,
                    'reason' => $reason,
                    'engine' => 'ai',
                ];
            }
        }

        // Check for simple BLOCK/ALLOW response
        if (str_contains(strtoupper($response), 'BLOCK')) {
            return [
                'detected' => true,
                'threat_type' => 'ai_blocked',
                'score' => 70,
                'severity' => 'high',
                'reason' => 'AI flagged as malicious',
                'engine' => 'ai',
            ];
        }

        return null;
    }

    /**
     * Check if AI detection is enabled
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Get current configuration
     */
    public function getConfig(): array
    {
        return [
            'enabled' => $this->enabled,
            'ollama_url' => $this->ollamaUrl,
            'ollama_model' => $this->ollamaModel,
            'sensitivity' => $this->sensitivity,
            'timeout' => $this->timeout,
        ];
    }
}
