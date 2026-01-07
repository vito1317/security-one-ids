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
        $this->agentToken = config('ids.agent_token') ?? env('AGENT_TOKEN', '');
        $this->agentName = config('ids.agent_name') ?? env('AGENT_NAME', gethostname());
    }

    /**
     * Register this agent with the central WAF
     */
    public function register(): bool
    {
        if (empty($this->wafUrl) || empty($this->agentToken)) {
            Log::warning('WAF_URL or AGENT_TOKEN not configured');
            return false;
        }

        try {
            $response = Http::timeout(30)->post("{$this->wafUrl}/api/ids/agents/register", [
                'token' => $this->agentToken,
                'name' => $this->agentName,
                'ip_address' => $this->getPublicIp(),
                'hostname' => gethostname(),
                'version' => config('app.version', '1.0.0'),
                'system_info' => $this->getSystemInfo(),
            ]);

            if ($response->successful()) {
                Log::info('Successfully registered with WAF', $response->json());
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
            return false;
        }

        try {
            $response = Http::timeout(10)->post("{$this->wafUrl}/api/ids/agents/heartbeat", [
                'token' => $this->agentToken,
                'system_info' => $this->getSystemInfo(),
            ]);

            if ($response->successful()) {
                $data = $response->json();
                // Could update local IDS/IPS settings based on response
                Log::debug('Heartbeat sent successfully', $data);
                return true;
            }

            return false;
        } catch (\Exception $e) {
            Log::error('Heartbeat failed: ' . $e->getMessage());
            return false;
        }
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
     * Get public IP address
     */
    protected function getPublicIp(): ?string
    {
        // Try to get local IP first
        $ip = gethostbyname(gethostname());
        if ($ip && $ip !== gethostname()) {
            return $ip;
        }

        // Fallback to external service
        try {
            $response = Http::timeout(5)->get('https://api.ipify.org');
            return $response->body();
        } catch (\Exception $e) {
            return '0.0.0.0';
        }
    }
}
