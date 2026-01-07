<?php

namespace App\Services\Detection;

use App\Services\TrafficAnalyzer;
use Illuminate\Support\Facades\Cache;

/**
 * Anomaly Detection Engine
 * 
 * Detects anomalies based on baseline deviations
 */
class AnomalyEngine
{
    private TrafficAnalyzer $analyzer;
    private const CACHE_PREFIX = 'anomaly:';
    private const BASELINE_TTL = 86400; // 24 hours

    public function __construct(TrafficAnalyzer $analyzer)
    {
        $this->analyzer = $analyzer;
    }

    /**
     * Analyze log entry for anomalies
     *
     * @param array $logData
     * @return array|null
     */
    public function analyze(array $logData): ?array
    {
        $anomalies = [];

        // Check request rate anomaly
        if ($rateAnomaly = $this->detectRateAnomaly($logData['ip'] ?? '')) {
            $anomalies[] = $rateAnomaly;
        }

        // Check request size anomaly
        if ($sizeAnomaly = $this->detectSizeAnomaly($logData)) {
            $anomalies[] = $sizeAnomaly;
        }

        // Check URL length anomaly
        if ($urlAnomaly = $this->detectURLLengthAnomaly($logData)) {
            $anomalies[] = $urlAnomaly;
        }

        // Check User-Agent anomaly
        if ($uaAnomaly = $this->detectUserAgentAnomaly($logData)) {
            $anomalies[] = $uaAnomaly;
        }

        // Check timing anomaly (business hours)
        if ($timeAnomaly = $this->detectTimingAnomaly($logData)) {
            $anomalies[] = $timeAnomaly;
        }

        if (empty($anomalies)) {
            return null;
        }

        return [
            'detected' => true,
            'type' => 'anomaly',
            'anomalies' => $anomalies,
            'severity' => $this->calculateSeverity($anomalies),
            'log_data' => $logData,
        ];
    }

    /**
     * Detect request rate anomaly
     */
    private function detectRateAnomaly(string $ip): ?array
    {
        if (empty($ip)) {
            return null;
        }

        $currentRate = $this->analyzer->trackRequest($ip, 60);
        $threshold = config('ids.anomaly.rate_threshold', 100); // requests per minute

        if ($currentRate > $threshold) {
            return [
                'type' => 'high_request_rate',
                'severity' => $currentRate > $threshold * 2 ? 'critical' : 'high',
                'current_rate' => $currentRate,
                'threshold' => $threshold,
                'ratio' => round($currentRate / $threshold, 2),
            ];
        }

        return null;
    }

    /**
     * Detect request size anomaly
     */
    private function detectSizeAnomaly(array $logData): ?array
    {
        $size = $logData['size'] ?? 0;
        $maxSize = config('ids.anomaly.max_request_size', 1048576); // 1MB

        if ($size > $maxSize) {
            return [
                'type' => 'large_request_size',
                'severity' => $size > $maxSize * 10 ? 'critical' : 'medium',
                'size' => $size,
                'max_size' => $maxSize,
                'ratio' => round($size / $maxSize, 2),
            ];
        }

        return null;
    }

    /**
     * Detect URL length anomaly
     */
    private function detectURLLengthAnomaly(array $logData): ?array
    {
        $uri = $logData['uri']['full'] ?? '';
        $length = strlen($uri);
        $maxLength = config('ids.anomaly.max_url_length', 2048);

        if ($length > $maxLength) {
            return [
                'type' => 'long_url',
                'severity' => $length > $maxLength * 2 ? 'high' : 'medium',
                'length' => $length,
                'max_length' => $maxLength,
            ];
        }

        return null;
    }

    /**
     * Detect User-Agent anomaly
     */
    private function detectUserAgentAnomaly(array $logData): ?array
    {
        $userAgent = strtolower($logData['user_agent'] ?? '');

        // Empty or very short User-Agent
        if (empty($userAgent) || strlen($userAgent) < 10) {
            return [
                'type' => 'suspicious_user_agent',
                'severity' => 'medium',
                'reason' => 'Empty or too short User-Agent',
                'user_agent' => $userAgent,
            ];
        }

        // Suspicious patterns
        $suspiciousPatterns = [
            'bot' => 'medium',
            'crawler' => 'low',
            'spider' => 'low',
            'scraper' => 'medium',
            'python' => 'medium',
            'perl' => 'medium',
            'java' => 'low',
        ];

        foreach ($suspiciousPatterns as $pattern => $severity) {
            if (str_contains($userAgent, $pattern)) {
                return [
                    'type' => 'suspicious_user_agent',
                    'severity' => $severity,
                    'reason' => "Contains suspicious pattern: $pattern",
                    'user_agent' => substr($userAgent, 0, 100),
                ];
            }
        }

        return null;
    }

    /**
     * Detect timing anomaly (non-business hours activity)
     */
    private function detectTimingAnomaly(array $logData): ?array
    {
        $timestamp = $logData['timestamp'] ?? now()->toDateTimeString();
        $hour = (int) date('H', strtotime($timestamp));

        // Business hours: 8 AM - 10 PM
        $businessStart = config('ids.anomaly.business_hours_start', 8);
        $businessEnd = config('ids.anomaly.business_hours_end', 22);

        if ($hour < $businessStart || $hour > $businessEnd) {
            // Check if it's a high-rate request
            $ip = $logData['ip'] ?? '';
            $currentRate = $this->analyzer->getIPRequestRate($ip, 60);

            if ($currentRate > 20) {
                return [
                    'type' => 'non_business_hours_activity',
                    'severity' => 'medium',
                    'hour' => $hour,
                    'request_rate' => $currentRate,
                ];
            }
        }

        return null;
    }

    /**
     * Calculate overall severity based on anomalies
     */
    private function calculateSeverity(array $anomalies): string
    {
        $severityScores = [
            'critical' => 4,
            'high' => 3,
            'medium' => 2,
            'low' => 1,
        ];

        $maxScore = 0;
        foreach ($anomalies as $anomaly) {
            $score = $severityScores[$anomaly['severity']] ?? 1;
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
     * Get or build baseline
     */
    public function getBaseline(): array
    {
        return Cache::remember(self::CACHE_PREFIX . 'baseline', self::BASELINE_TTL, function () {
            // Default baseline values
            return [
                'avg_qps' => 10,
                'avg_request_size' => 50000, // 50KB
                'avg_requests_per_ip' => 50,
                'error_rate' => 0.05,
            ];
        });
    }

    /**
     * Update baseline with new data
     */
    public function updateBaseline(array $newBaseline): void
    {
        Cache::put(self::CACHE_PREFIX . 'baseline', $newBaseline, self::BASELINE_TTL);
    }
}
