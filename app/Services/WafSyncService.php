<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class WafSyncService
{
    protected string $wafUrl;
    protected string $agentToken;
    protected string $agentName;

    public function __construct()
    {
        $this->wafUrl = rtrim(config('ids.waf_url') ?? env('WAF_URL', ''), '/');
        
        // Prefer cached WAF-assigned token over .env token (registration returns correct token)
        $cachedToken = cache()->get('waf_agent_token');
        $envToken = config('ids.agent_token') ?? env('AGENT_TOKEN', '');
        $this->agentToken = !empty($cachedToken) ? $cachedToken : $envToken;
        
        $this->agentName = config('ids.agent_name') ?? env('AGENT_NAME', gethostname());
    }

    /**
     * Register this agent with the central WAF
     */
    public function register(): bool
    {
        // Debug logging
        Log::debug('WafSync register() called', [
            'wafUrl' => $this->wafUrl,
            'agentToken' => substr($this->agentToken, 0, 10) . '...',
            'agentName' => $this->agentName,
        ]);

        if (empty($this->wafUrl) || empty($this->agentToken)) {
            Log::warning('WAF_URL or AGENT_TOKEN not configured', [
                'wafUrl_empty' => empty($this->wafUrl),
                'agentToken_empty' => empty($this->agentToken),
                'env_WAF_URL' => env('WAF_URL'),
                'config_ids.waf_url' => config('ids.waf_url'),
            ]);
            return false;
        }

        try {
            $response = Http::timeout(30)->post("{$this->wafUrl}/api/ids/agents/register", [
                'token' => $this->agentToken,
                'name' => $this->agentName,
                'ip_address' => $this->getPublicIp(),
                'hostname' => gethostname(),
                'version' => config('app.version', '1.0.0'),
                'platform' => $this->detectPlatform(),
                'system_info' => $this->getSystemInfo(),
            ]);

            if ($response->successful()) {
                $data = $response->json();
                Log::info('Successfully registered with WAF', $data);
                
                // Store the WAF-assigned token for future use
                if (!empty($data['token'])) {
                    cache()->put('waf_agent_token', $data['token'], now()->addDays(30));
                }
                
                // Store the agent ID for alert syncing
                if (!empty($data['agent_id'])) {
                    cache()->put('ids_agent_id', $data['agent_id'], now()->addDays(30));
                }
                
                return true;
            }

            Log::error('Failed to register with WAF', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return false;
        } catch (\Exception $e) {
            Log::error('Exception during WAF registration: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Send heartbeat to WAF
     */
    public function heartbeat(): bool
    {
        if (empty($this->wafUrl) || empty($this->agentToken)) {
            Log::warning('WAF_URL or AGENT_TOKEN not configured for heartbeat');
            return false;
        }

        try {
            $response = Http::timeout(10)->post("{$this->wafUrl}/api/ids/agents/heartbeat", [
                'token' => $this->agentToken,
                'name' => $this->agentName,
                'system_info' => $this->getSystemInfo(),
            ]);

            if ($response->successful()) {
                $data = $response->json();
                Log::debug('Heartbeat sent successfully', $data);
                
                // Sync config from WAF Hub (including Ollama settings)
                if (isset($data['config'])) {
                    $this->syncConfigFromHub($data['config']);
                }
                
                return true;
            }

            // If agent not found (404), try to register
            if ($response->status() === 404) {
                Log::info('Agent not found, attempting registration...');
                return $this->register();
            }

            Log::warning('Heartbeat failed', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return false;
        } catch (\Exception $e) {
            Log::error('Heartbeat exception: ' . $e->getMessage());
            // On connection error, try registration
            if (str_contains($e->getMessage(), 'Connection') || str_contains($e->getMessage(), 'cURL')) {
                Log::info('Connection error, will try registration on next sync');
            }
            return false;
        }
    }

    /**
     * Sync config received from WAF Hub
     */
    private function syncConfigFromHub(array $config): void
    {
        $configPath = storage_path('app/waf_config.json');
        
        // Read existing config
        $existingConfig = [];
        if (file_exists($configPath)) {
            $existingConfig = json_decode(file_get_contents($configPath), true) ?: [];
        }
        
        // Merge with new config
        $mergedConfig = array_merge($existingConfig, $config);
        
        // Save to storage
        file_put_contents($configPath, json_encode($mergedConfig, JSON_PRETTY_PRINT));
        
        Log::info('Config synced from WAF Hub', [
            'ollama_url' => $config['ollama']['url'] ?? 'not set',
            'ollama_model' => $config['ollama']['model'] ?? 'not set',
        ]);
    }

    /**
     * Get synced config from local storage
     */
    public function getSyncedConfig(): array
    {
        $configPath = storage_path('app/waf_config.json');
        
        if (file_exists($configPath)) {
            return json_decode(file_get_contents($configPath), true) ?: [];
        }
        
        return [];
    }

    /**
     * Report alerts to WAF
     */
    public function reportAlerts(array $alerts): bool
    {
        if (empty($this->wafUrl) || empty($this->agentToken) || empty($alerts)) {
            return false;
        }

        try {
            $response = Http::timeout(30)->post("{$this->wafUrl}/api/ids/agents/alerts", [
                'token' => $this->agentToken,
                'alerts' => $alerts,
            ]);

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Failed to report alerts: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch rules from WAF
     */
    public function fetchRules(): ?array
    {
        if (empty($this->wafUrl) || empty($this->agentToken)) {
            return null;
        }

        try {
            $response = Http::timeout(30)->get("{$this->wafUrl}/api/ids/agents/rules", [
                'token' => $this->agentToken,
            ]);

            if ($response->successful()) {
                return $response->json();
            }

            return null;
        } catch (\Exception $e) {
            Log::error('Failed to fetch rules: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Sync rules from WAF to local IdsSignature database
     */
    public function syncRulesToDatabase(array $rules): int
    {
        $synced = 0;
        
        foreach ($rules as $rule) {
            try {
                \App\Models\IdsSignature::updateOrCreate(
                    ['name' => $rule['name']],
                    [
                        'description' => $rule['description'] ?? null,
                        'pattern' => $rule['pattern'] ?? '',
                        'category' => $rule['category'] ?? 'general',
                        'severity' => $rule['severity'] ?? 'medium',
                        'match_uri' => true,
                        'match_user_agent' => false,
                        'match_referer' => false,
                        'enabled' => $rule['enabled'] ?? true,
                    ]
                );
                $synced++;
            } catch (\Exception $e) {
                Log::error('Failed to sync rule: ' . ($rule['name'] ?? 'unknown'), [
                    'error' => $e->getMessage(),
                ]);
            }
        }
        
        Log::info("Synced {$synced} rules from WAF to local database");
        return $synced;
    }

    /**
     * Upload local signatures to WAF Hub
     */
    public function uploadSignatures(): int
    {
        if (empty($this->wafUrl)) {
            Log::warning('WAF_URL not configured for upload');
            return 0;
        }

        // Use the WAF-assigned token (from registration) if available
        $token = cache()->get('waf_agent_token', $this->agentToken);
        if (empty($token)) {
            Log::warning('No agent token available for upload');
            return 0;
        }

        // Get all local signatures
        $signatures = \App\Models\IdsSignature::where('enabled', true)->get();
        
        if ($signatures->isEmpty()) {
            Log::info('No signatures to upload');
            return 0;
        }

        try {
            $response = Http::timeout(60)->post("{$this->wafUrl}/api/ids/agents/sync-rules", [
                'token' => $token,
                'signatures' => $signatures->map(fn($sig) => [
                    'name' => $sig->name,
                    'pattern' => $sig->pattern,
                    'category' => $sig->category,
                    'severity' => $sig->severity,
                    'description' => $sig->description,
                ])->toArray(),
            ]);

            if ($response->successful()) {
                $data = $response->json();
                Log::info('Successfully uploaded signatures to WAF', $data);
                return $data['synced'] ?? 0;
            }

            Log::error('Failed to upload signatures', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return 0;
        } catch (\Exception $e) {
            Log::error('Exception during signature upload: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get system information
     */
    protected function getSystemInfo(): array
    {
        return [
            'os' => PHP_OS,
            'php_version' => PHP_VERSION,
            'memory_usage' => memory_get_usage(true),
            'load_average' => function_exists('sys_getloadavg') ? sys_getloadavg() : [],
            'uptime' => $this->getUptime(),
        ];
    }

    /**
     * Get server uptime
     */
    protected function getUptime(): ?int
    {
        if (file_exists('/proc/uptime')) {
            $uptime = file_get_contents('/proc/uptime');
            return (int) explode(' ', $uptime)[0];
        }
        return null;
    }

    /**
     * Get public IP address (real external IP, not Docker internal)
     */
    protected function getPublicIp(): ?string
    {
        // Check cache first
        $cachedIp = cache()->get('agent_public_ip');
        if ($cachedIp) {
            return $cachedIp;
        }

        // Try multiple external IP services
        $services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com',
            'https://ipinfo.io/ip',
        ];

        foreach ($services as $service) {
            try {
                $response = Http::timeout(5)->get($service);
                if ($response->successful()) {
                    $ip = trim($response->body());
                    // Validate IP format
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        // Cache for 1 hour
                        cache()->put('agent_public_ip', $ip, now()->addHour());
                        return $ip;
                    }
                }
            } catch (\Exception $e) {
                continue;
            }
        }

        // Fallback to local IP if all external services fail
        $ip = gethostbyname(gethostname());
        if ($ip && $ip !== gethostname()) {
            return $ip;
        }

        return '0.0.0.0';
    }

    /**
     * Sync alert to WAF Hub
     *
     * @param array $alertData
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncAlert(array $alertData): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for alerts');
            return null;
        }

        try {
            $response = Http::timeout(10)
                ->withHeaders([
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'X-Requested-With' => 'XMLHttpRequest',  // Makes Laravel treat as AJAX
                ])
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/alerts", [
                    'agent_id' => $this->getAgentId(),
                    'alert' => $alertData,
                ]);

            if ($response->successful()) {
                Log::info('Alert synced to WAF Hub', [
                    'ip' => $alertData['source_ip'] ?? 'unknown',
                    'severity' => $alertData['severity'] ?? 'unknown',
                ]);
            } else {
                Log::error('WAF Hub rejected alert', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync alert to WAF Hub', [
                'error' => $e->getMessage(),
                'ip' => $alertData['source_ip'] ?? 'unknown',
            ]);
            return null;
        }
    }

    /**
     * Get agent ID from config or cache
     */
    private function getAgentId(): ?int
    {
        // Try to get from environment first
        if ($agentId = env('IDS_AGENT_ID')) {
            return (int) $agentId;
        }

        // Or from cache (set during registration)
        return cache('ids_agent_id');
    }

    /**
     * Check if WAF sync is properly configured
     */
    private function isConfigured(): bool
    {
        return !empty($this->agentToken) && !empty($this->wafUrl);
    }

    /**
     * Sync blocked IP to WAF Hub
     *
     * @param array $blockData
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncBlockedIP(array $blockData): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for blocking');
            return null;
        }

        try {
            $response = Http::timeout(10)
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/block-ip", [
                    'agent_id' => $this->getAgentId(),
                    'block' => $blockData,
                ]);

            if ($response->successful()) {
                Log::info('Blocked IP synced to WAF Hub', [
                    'ip' => $blockData['ip'] ?? 'unknown',
                ]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync blocked IP', [
                'error' => $e->getMessage(),
                'ip' => $blockData['ip'] ?? 'unknown',
            ]);
            return null;
        }
    }

    /**
     * Sync IP unblock to WAF Hub
     *
     * @param string $ip
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncUnblockIP(string $ip): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for unblocking');
            return null;
        }

        try {
            $response = Http::timeout(10)
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/unblock-ip", [
                    'agent_id' => $this->getAgentId(),
                    'ip' => $ip,
                ]);

            if ($response->successful()) {
                Log::info('Unblocked IP synced to WAF Hub', ['ip' => $ip]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync IP unblock', [
                'error' => $e->getMessage(),
                'ip' => $ip,
            ]);
            return null;
        }
    }

    /**
     * Fetch agent configuration from WAF Hub
     */
    public function fetchAgentConfig(): ?array
    {
        if (!$this->isConfigured()) {
            return null;
        }

        try {
            $response = Http::timeout(10)
                ->withToken($this->agentToken)
                ->get("{$this->wafUrl}/api/ids/agents/config");

            if ($response->successful()) {
                $config = $response->json()['config'] ?? [];
                // Cache for 1 hour
                cache()->put('waf_agent_config', $config, now()->addHour());
                Log::info('Agent configuration fetched and cached from WAF Hub');
                return $config;
            }

            Log::warning('Failed to fetch agent config', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return null;
        } catch (\Exception $e) {
            Log::error('Exception during agent config fetch: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get cached agent configuration
     */
    public function getCachedConfig(): array
    {
        return cache()->get('waf_agent_config') ?? $this->fetchAgentConfig() ?? [];
    }

    /**
     * Detect the current platform
     */
    private function detectPlatform(): string
    {
        // Check if running in Docker (likely server deployment)
        if (file_exists('/.dockerenv') || file_exists('/run/.containerenv')) {
            return 'server';
        }
        
        if (stripos(PHP_OS, 'WIN') === 0) {
            return 'windows';
        } elseif (stripos(PHP_OS, 'Darwin') !== false) {
            return 'macos';
        }
        
        // Check if it's a desktop Linux vs server
        $isDesktop = getenv('DISPLAY') || getenv('WAYLAND_DISPLAY') || file_exists('/usr/share/xsessions');
        
        return $isDesktop ? 'desktop' : 'linux';
    }
}
