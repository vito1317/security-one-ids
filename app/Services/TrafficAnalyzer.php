<?php

namespace App\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * Traffic Analyzer Service
 * 
 * Analyzes traffic patterns for anomaly detection and baseline establishment
 */
class TrafficAnalyzer
{
    private const CACHE_PREFIX = 'traffic_stats:';
    private const CACHE_TTL = 3600; // 1 hour

    /**
     * Calculate Queries Per Second (QPS) for a given time window
     *
     * @param Collection $logs Collection of parsed log entries
     * @param int $timeWindow Time window in seconds (default: 60)
     * @return float Average QPS
     */
    public function calculateQPS(Collection $logs, int $timeWindow = 60): float
    {
        if ($logs->isEmpty()) {
            return 0.0;
        }

        $requestCount = $logs->count();
        
        // Calculate actual time span
        $timestamps = $logs->pluck('timestamp')->map(fn($ts) => strtotime($ts));
        $timeSpan = $timestamps->max() - $timestamps->min();
        
        if ($timeSpan === 0) {
            return (float) $requestCount;
        }

        return round($requestCount / max($timeSpan, 1), 2);
    }

    /**
     * Analyze IP request frequency
     *
     * @param Collection $logs
     * @param int $threshold Alert threshold (requests per minute)
     * @return array ['ip' => count, ...]
     */
    public function analyzeIPFrequency(Collection $logs, int $threshold = 100): array
    {
        $ipCounts = $logs->groupBy('ip')
            ->map(fn($group) => $group->count())
            ->sortDesc();

        return [
            'top_ips' => $ipCounts->take(10)->toArray(),
            'suspicious_ips' => $ipCounts->filter(fn($count) => $count > $threshold)->toArray(),
            'unique_ips' => $ipCounts->count(),
            'total_requests' => $logs->count(),
        ];
    }

    /**
     * Analyze URL access patterns
     *
     * @param Collection $logs
     * @return array
     */
    public function analyzeURLPatterns(Collection $logs): array
    {
        $urlCounts = $logs->groupBy('uri.path')
            ->map(fn($group) => [
                'count' => $group->count(),
                'methods' => $group->pluck('method')->unique()->values()->toArray(),
                'status_codes' => $group->pluck('status')->unique()->values()->toArray(),
                'avg_size' => round($group->avg('size'), 2),
            ])
            ->sortByDesc('count');

        $errorUrls = $logs->filter(fn($log) => $log['status'] >= 400)
            ->groupBy('uri.path')
            ->map(fn($group) => $group->count())
            ->sortDesc();

        return [
            'top_urls' => $urlCounts->take(20)->toArray(),
            'error_urls' => $errorUrls->take(10)->toArray(),
            'unique_urls' => $urlCounts->count(),
            'total_requests' => $logs->count(),
        ];
    }

    /**
     * Analyze User-Agent distribution
     *
     * @param Collection $logs
     * @return array
     */
    public function analyzeUserAgents(Collection $logs): array
    {
        $userAgents = $logs->groupBy('user_agent')
            ->map(fn($group) => $group->count())
            ->sortDesc();

        // Detect suspicious User-Agents
        $suspiciousPatterns = [
            'bot', 'crawler', 'spider', 'scraper',
            'curl', 'wget', 'python', 'perl',
            'sqlmap', 'nikto', 'nmap', 'masscan',
            'burp', 'metasploit', 'acunetix',
        ];

        $suspicious = $userAgents->filter(function ($count, $ua) use ($suspiciousPatterns) {
            $uaLower = strtolower($ua);
            foreach ($suspiciousPatterns as $pattern) {
                if (str_contains($uaLower, $pattern)) {
                    return true;
                }
            }
            return false;
        });

        // Categorize by type
        $categories = [
            'browsers' => 0,
            'bots' => 0,
            'tools' => 0,
            'unknown' => 0,
        ];

        foreach ($logs as $log) {
            $ua = strtolower($log['user_agent'] ?? '');
            
            if (str_contains($ua, 'mozilla') || str_contains($ua, 'chrome') || str_contains($ua, 'safari')) {
                $categories['browsers']++;
            } elseif (str_contains($ua, 'bot') || str_contains($ua, 'crawler')) {
                $categories['bots']++;
            } elseif (str_contains($ua, 'curl') || str_contains($ua, 'wget') || str_contains($ua, 'python')) {
                $categories['tools']++;
            } else {
                $categories['unknown']++;
            }
        }

        return [
            'top_user_agents' => $userAgents->take(15)->toArray(),
            'suspicious_agents' => $suspicious->toArray(),
            'categories' => $categories,
            'unique_agents' => $userAgents->count(),
        ];
    }

    /**
     * Generate comprehensive traffic statistics
     *
     * @param Collection $logs
     * @return array
     */
    public function generateStats(Collection $logs): array
    {
        return [
            'summary' => [
                'total_requests' => $logs->count(),
                'unique_ips' => $logs->pluck('ip')->unique()->count(),
                'unique_urls' => $logs->pluck('uri.path')->unique()->count(),
                'time_range' => [
                    'start' => $logs->min('timestamp'),
                    'end' => $logs->max('timestamp'),
                ],
            ],
            'qps' => [
                '1min' => $this->calculateQPS($logs, 60),
                '5min' => $this->calculateQPS($logs, 300),
                '15min' => $this->calculateQPS($logs, 900),
            ],
            'http_methods' => $logs->groupBy('method')->map->count()->toArray(),
            'status_codes' => $logs->groupBy('status')->map->count()->toArray(),
            'ip_analysis' => $this->analyzeIPFrequency($logs),
            'url_analysis' => $this->analyzeURLPatterns($logs),
            'user_agent_analysis' => $this->analyzeUserAgents($logs),
        ];
    }

    /**
     * Get request rate for a specific IP
     *
     * @param string $ip
     * @param int $timeWindow Time window in seconds
     * @return int Request count in time window
     */
    public function getIPRequestRate(string $ip, int $timeWindow = 60): int
    {
        $cacheKey = self::CACHE_PREFIX . "ip_rate:{$ip}:{$timeWindow}";
        
        return Cache::remember($cacheKey, 10, function () use ($ip, $timeWindow) {
            // This would query actual log storage in production
            // For now, return from cache/memory
            return Cache::get(self::CACHE_PREFIX . "ip_requests:{$ip}", 0);
        });
    }

    /**
     * Track request for rate limiting
     *
     * @param string $ip
     * @param int $ttl Time to live in seconds
     * @return int Current count
     */
    public function trackRequest(string $ip, int $ttl = 60): int
    {
        $cacheKey = self::CACHE_PREFIX . "ip_requests:{$ip}";
        
        $current = Cache::get($cacheKey, 0);
        $newCount = $current + 1;
        
        Cache::put($cacheKey, $newCount, $ttl);
        
        return $newCount;
    }

    /**
     * Detect traffic anomalies based on historical baseline
     *
     * @param Collection $currentLogs Recent logs
     * @param array $baseline Historical baseline data
     * @return array Detected anomalies
     */
    public function detectAnomalies(Collection $currentLogs, array $baseline): array
    {
        $anomalies = [];
        $current = $this->generateStats($currentLogs);

        // QPS anomaly
        $currentQPS = $current['qps']['1min'];
        $baselineQPS = $baseline['qps']['1min'] ?? 0;
        
        if ($baselineQPS > 0 && $currentQPS > ($baselineQPS * 5)) {
            $anomalies[] = [
                'type' => 'qps_spike',
                'severity' => 'high',
                'current' => $currentQPS,
                'baseline' => $baselineQPS,
                'ratio' => round($currentQPS / $baselineQPS, 2),
            ];
        }

        // Suspicious User-Agent spike
        $suspiciousCount = count($current['user_agent_analysis']['suspicious_agents']);
        $baselineSuspicious = $baseline['user_agent_analysis']['suspicious_count'] ?? 0;
        
        if ($suspiciousCount > ($baselineSuspicious * 2) + 10) {
            $anomalies[] = [
                'type' => 'suspicious_user_agents',
                'severity' => 'medium',
                'current' => $suspiciousCount,
                'baseline' => $baselineSuspicious,
            ];
        }

        // Error rate anomaly
        $errorCount = array_sum($current['status_codes'] ?? []);
        $totalRequests = $current['summary']['total_requests'];
        $errorRate = $totalRequests > 0 ? ($errorCount / $totalRequests) : 0;
        $baselineErrorRate = $baseline['error_rate'] ?? 0.05;
        
        if ($errorRate > 0.3 && $errorRate > ($baselineErrorRate * 3)) {
            $anomalies[] = [
                'type' => 'high_error_rate',
                'severity' => 'high',
                'current' => round($errorRate * 100, 2) . '%',
                'baseline' => round($baselineErrorRate * 100, 2) . '%',
            ];
        }

        return $anomalies;
    }

    /**
     * Build traffic baseline from historical data
     *
     * @param Collection $historicalLogs
     * @return array Baseline statistics
     */
    public function buildBaseline(Collection $historicalLogs): array
    {
        $stats = $this->generateStats($historicalLogs);
        
        $errorCount = 0;
        foreach ($stats['status_codes'] ?? [] as $code => $count) {
            if ($code >= 400) {
                $errorCount += $count;
            }
        }
        
        return [
            'qps' => $stats['qps'],
            'avg_requests_per_ip' => $stats['summary']['total_requests'] / max($stats['summary']['unique_ips'], 1),
            'user_agent_analysis' => [
                'suspicious_count' => count($stats['user_agent_analysis']['suspicious_agents']),
            ],
            'error_rate' => $stats['summary']['total_requests'] > 0 
                ? $errorCount / $stats['summary']['total_requests'] 
                : 0,
            'generated_at' => now()->toDateTimeString(),
        ];
    }
}
