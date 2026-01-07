<?php

namespace App\Services\Detection;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Collection;

/**
 * Behavior Analysis Engine
 * 
 * Detects malicious behavior patterns
 */
class BehaviorEngine
{
    private const CACHE_PREFIX = 'behavior:';
    private const CACHE_TTL = 300; // 5 minutes

    /**
     * Analyze log data for behavioral patterns
     *
     * @param array $logData
     * @return array|null
     */
    public function analyze(array $logData): ?array
    {
        $behaviors = [];

        // Check scanning behavior
        if ($scanning = $this->detectScanning($logData)) {
            $behaviors[] = $scanning;
        }

        // Check brute force
        if ($bruteForce = $this->detectBruteForce($logData)) {
            $behaviors[] = $bruteForce;
        }

        // Check crawler behavior
        if ($crawler = $this->detectCrawler($logData)) {
            $behaviors[] = $crawler;
        }

        // Check rapid successive requests
        if ($rapid = $this->detectRapidRequests($logData)) {
            $behaviors[] = $rapid;
        }

        if (empty($behaviors)) {
            return null;
        }

        return [
            'detected' => true,
            'type' => 'behavior',
            'behaviors' => $behaviors,
            'severity' => $this->calculateSeverity($behaviors),
            'score' => $this->calculateBehaviorScore($behaviors),
        ];
    }

    /**
     * Detect scanning behavior (accessing multiple URLs rapidly)
     */
    private function detectScanning(array $logData): ?array
    {
        $ip = $logData['ip'] ?? '';
        if (empty($ip)) {
            return null;
        }

        $cacheKey = self::CACHE_PREFIX . "urls:{$ip}";
        $urls = Cache::get($cacheKey, []);
        
        // Track unique URLs accessed
        $url = $logData['uri']['path'] ?? '';
        if (!in_array($url, $urls)) {
            $urls[] = $url;
            Cache::put($cacheKey, $urls, self::CACHE_TTL);
        }

        // If accessing many different URLs quickly, likely scanning
        $urlCount = count($urls);
        if ($urlCount > 20) {
            return [
                'type' => 'scanning',
                'severity' => $urlCount > 50 ? 'high' : 'medium',
                'url_count' => $urlCount,
                'time_window' => self::CACHE_TTL,
            ];
        }

        return null;
    }

    /**
     * Detect brute force attack (repeated failed login attempts)
     */
    private function detectBruteForce(array $logData): ?array
    {
        $ip = $logData['ip'] ?? '';
        $uri = $logData['uri']['path'] ?? '';
        $status = $logData['status'] ?? 200;

        // Check if this is a login endpoint
        $loginPaths = ['/login', '/api/login', '/signin', '/auth'];
        $isLoginPath = false;
        foreach ($loginPaths as $path) {
            if (str_contains($uri, $path)) {
                $isLoginPath = true;
                break;
            }
        }

        if (!$isLoginPath) {
            return null;
        }

        // Track failed login attempts
        if (in_array($status, [401, 403])) {
            $cacheKey = self::CACHE_PREFIX . "failed_login:{$ip}";
            $attempts = Cache::get($cacheKey, 0) + 1;
            Cache::put($cacheKey, $attempts, self::CACHE_TTL);

            if ($attempts > 5) {
                return [
                    'type' => 'brute_force',
                    'severity' => $attempts > 10 ? 'critical' : 'high',
                    'failed_attempts' => $attempts,
                    'target_path' => $uri,
                ];
            }
        }

        return null;
    }

    /**
     * Detect crawler/scraper behavior
     */
    private function detectCrawler(array $logData): ?array
    {
        $userAgent = strtolower($logData['user_agent'] ?? '');
        $ip = $logData['ip'] ?? '';

        // Known crawler patterns
        $crawlerPatterns = [
            'headless' => 'high',
            'selenium' => 'high',
            'puppeteer' => 'high',
            'phantomjs' => 'high',
            'scrapy' => 'high',
            'beautifulsoup' => 'medium',
            'wget' => 'medium',
            'curl' => 'low',
        ];

        foreach ($crawlerPatterns as $pattern => $severity) {
            if (str_contains($userAgent, $pattern)) {
                // Track crawler activity
                $cacheKey = self::CACHE_PREFIX . "crawler:{$ip}";
                $requests = Cache::get($cacheKey, 0) + 1;
                Cache::put($cacheKey, $requests, self::CACHE_TTL);

                return [
                    'type' => 'crawler',
                    'severity' => $severity,
                    'pattern' => $pattern,
                    'user_agent' => substr($userAgent, 0, 100),
                    'request_count' => $requests,
                ];
            }
        }

        return null;
    }

    /**
     * Detect rapid successive requests from same IP
     */
    private function detectRapidRequests(array $logData): ?array
    {
        $ip = $logData['ip'] ?? '';
        if (empty($ip)) {
            return null;
        }

        $cacheKey = self::CACHE_PREFIX . "rapid:{$ip}";
        $timestamps = Cache::get($cacheKey, []);
        
        // Add current timestamp
        $now = time();
        $timestamps[] = $now;
        
        // Keep only last 10 seconds
        $timestamps = array_filter($timestamps, fn($ts) => ($now - $ts) < 10);
        Cache::put($cacheKey, $timestamps, 60);

        // If more than 10 requests in 10 seconds
        $count = count($timestamps);
        if ($count > 10) {
            return [
                'type' => 'rapid_requests',
                'severity' => $count > 30 ? 'high' : 'medium',
                'request_count' => $count,
                'time_window' => 10,
                'rate' => round($count / 10, 2) . ' req/s',
            ];
        }

        return null;
    }

    /**
     * Calculate overall severity from behaviors
     */
    private function calculateSeverity(array $behaviors): string
    {
        $severityScores = [
            'critical' => 4,
            'high' => 3,
            'medium' => 2,
            'low' => 1,
        ];

        $maxScore = 0;
        foreach ($behaviors as $behavior) {
            $score = $severityScores[$behavior['severity']] ?? 1;
            if ($score > $maxScore) {
                $maxScore = $score;
            }
        }

        foreach ($severityScores as $severity => $score) {
            if ($score === $maxScore) {
                return $severity;
            }
        }

        return 'low';
    }

    /**
     * Calculate behavior score (0-100)
     */
    private function calculateBehaviorScore(array $behaviors): int
    {
        $score = 0;

        foreach ($behaviors as $behavior) {
            switch ($behavior['type']) {
                case 'brute_force':
                    $score += min($behavior['failed_attempts'] * 10, 50);
                    break;
                case 'scanning':
                    $score += min($behavior['url_count'] * 2, 40);
                    break;
                case 'crawler':
                    $score += 20;
                    break;
                case 'rapid_requests':
                    $score += min($behavior['request_count'], 30);
                    break;
            }
        }

        return min($score, 100);
    }

    /**
     * Analyze batch of logs for behavioral patterns
     */
    public function analyzeBatch(Collection $logs): Collection
    {
        return $logs->map(function ($log) {
            $result = $this->analyze($log);
            if ($result) {
                $result['log_data'] = $log;
            }
            return $result;
        })->filter();
    }
}
