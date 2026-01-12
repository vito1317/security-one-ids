<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Alert Service
 * 
 * Generates and manages security alerts
 */
class AlertService
{
    private WafSyncService $wafSync;

    public function __construct(WafSyncService $wafSync)
    {
        $this->wafSync = $wafSync;
    }

    /**
     * Create alert from detection results
     *
     * @param array $logData Original log entry
     * @param array $detections Detection results
     * @return array Alert data
     */
    public function createAlert(array $logData, array $detections): array
    {
        $severity = $this->determineSeverity($detections);
        $category = $this->determineCategory($detections);
        
        // Format detections before creating alert
        $formattedDetections = $this->formatDetections($detections);
        
        // Debug log to trace what we're sending  
        Log::debug('Creating alert with detections', [
            'source_ip' => $logData['ip'] ?? 'unknown',
            'raw_detections' => array_keys($detections),
            'formatted_detections' => substr($formattedDetections, 0, 200),
        ]);
        
        $alert = [
            'source_ip' => $logData['ip'] ?? 'unknown',
            'uri' => $logData['uri']['full'] ?? '',
            'method' => $logData['method'] ?? '',
            'user_agent' => $logData['user_agent'] ?? '',
            'severity' => $severity,
            'category' => $category,
            'timestamp' => $logData['timestamp'] ?? now()->toDateTimeString(),
            'detections' => $formattedDetections,
            'raw_log' => $this->formatRawLog($logData),
        ];

        // Sync to WAF Hub
        $this->syncToWaf($alert);

        return $alert;
    }

    /**
     * Determine overall severity
     */
    private function determineSeverity(array $detections): string
    {
        $severityLevels = ['critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1];
        $maxSeverity = 'low';
        $maxScore = 0;

        foreach ($detections as $detection) {
            $severity = $detection['severity'] ?? 'low';
            $score = $severityLevels[$severity] ?? 1;
            
            if ($score > $maxScore) {
                $maxScore = $score;
                $maxSeverity = $severity;
            }
        }

        return $maxSeverity;
    }

    /**
     * Determine alert category
     */
    private function determineCategory(array $detections): string
    {
        // Prioritize signature detections
        if (isset($detections['signature'])) {
            return $detections['signature']['category'] ?? 'unknown';
        }

        // Then anomaly
        if (isset($detections['anomaly'])) {
            return 'anomaly';
        }

        // Then behavior
        if (isset($detections['behavior'])) {
            return 'behavior';
        }

        return 'unknown';
    }

    /**
     * Format detection details for storage
     */
    private function formatDetections(array $detections): string
    {
        $formatted = [];

        if (isset($detections['signature'])) {
            $sig = $detections['signature'];
            $formatted[] = sprintf(
                "[SIGNATURE] %s - %s (Severity: %s, Category: %s)",
                $sig['signature_name'] ?? 'Unknown',
                $sig['description'] ?? 'Pattern match detected',
                $sig['severity'] ?? 'unknown',
                $sig['category'] ?? 'unknown'
            );
            
            if (!empty($sig['matched_value'])) {
                $formatted[] = "  Matched: " . substr($sig['matched_value'], 0, 200);
            }
        }

        if (isset($detections['anomaly'])) {
            $anom = $detections['anomaly'];
            if (isset($anom['anomalies']) && is_array($anom['anomalies'])) {
                foreach ($anom['anomalies'] as $anomaly) {
                    $formatted[] = sprintf(
                        "[ANOMALY] %s - %s (Severity: %s)",
                        $anomaly['type'] ?? 'Unknown type',
                        $anomaly['details'] ?? 'Anomalous behavior detected',
                        $anomaly['severity'] ?? 'medium'
                    );
                }
            } else {
                $formatted[] = "[ANOMALY] Anomalous request pattern detected (Severity: " . ($anom['severity'] ?? 'medium') . ")";
            }
        }

        if (isset($detections['behavior'])) {
            $behav = $detections['behavior'];
            $behavType = $behav['type'] ?? 'suspicious_activity';
            $behavDesc = $behav['description'] ?? 'Suspicious request behavior detected';
            $formatted[] = sprintf(
                "[BEHAVIOR] %s - %s (Severity: %s)",
                ucfirst(str_replace('_', ' ', $behavType)),
                $behavDesc,
                $behav['severity'] ?? 'medium'
            );
        }

        // AI Detection results
        if (isset($detections['ai'])) {
            $ai = $detections['ai'];
            $formatted[] = sprintf(
                "[AI] %s - %s (Score: %d, Severity: %s)",
                strtoupper($ai['threat_type'] ?? 'ai_detected'),
                $ai['reason'] ?? 'AI detected potential threat',
                $ai['score'] ?? 0,
                $ai['severity'] ?? 'medium'
            );
        }

        // If no formatted content, provide a default
        if (empty($formatted)) {
            $formatted[] = "[DETECTION] Security event detected";
        }

        return implode("\n", $formatted);
    }

    /**
     * Format raw log for storage
     */
    private function formatRawLog(array $logData): string
    {
        return sprintf(
            "%s - %s %s - Status: %s - Size: %s - UA: %s",
            $logData['ip'] ?? '',
            $logData['method'] ?? '',
            $logData['uri']['full'] ?? '',
            $logData['status'] ?? '',
            $logData['size'] ?? '',
            substr($logData['user_agent'] ?? '', 0, 100)
        );
    }

    /**
     * Sync alert to WAF Hub
     */
    private function syncToWaf(array $alert): void
    {
        try {
            $response = $this->wafSync->syncAlert($alert);
            
            if ($response && $response->successful()) {
                Log::info('Alert synced to WAF', ['ip' => $alert['source_ip']]);
            } else {
                Log::error('Failed to sync alert to WAF', [
                    'ip' => $alert['source_ip'],
                    'status' => $response ? $response->status() : 'no response',
                ]);
            }
        } catch (\Exception $e) {
            Log::error('Exception syncing alert to WAF', [
                'ip' => $alert['source_ip'],
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Batch create alerts
     */
    public function createAlerts(array $logsWithDetections): array
    {
        $alerts = [];

        foreach ($logsWithDetections as $item) {
            if (isset($item['log_data']) && isset($item['detections'])) {
                $alerts[] = $this->createAlert($item['log_data'], $item['detections']);
            }
        }

        return $alerts;
    }

    /**
     * Check if alert should be rate-limited
     */
    public function shouldRateLimit(string $ip, string $category): bool
    {
        $cacheKey = "alert_rate_limit:{$ip}:{$category}";
        $count = cache()->get($cacheKey, 0);
        
        $limit = config('ids.alerts.rate_limit', 10); // alerts per minute
        
        if ($count >= $limit) {
            return true;
        }

        cache()->put($cacheKey, $count + 1, 60);
        return false;
    }
}
