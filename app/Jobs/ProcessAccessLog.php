<?php

namespace App\Jobs;

use App\Services\LogCollectorService;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

/**
 * Process Access Log Job
 * 
 * Async job to process Nginx access logs and detect threats
 */
class ProcessAccessLog implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * The number of times the job may be attempted.
     */
    public int $tries = 3;

    /**
     * The number of seconds to wait before retrying the job.
     */
    public int $backoff = 10;

    /**
     * Constructor
     *
     * @param array $logData Parsed log data
     */
    public function __construct(
        public array $logData
    ) {
        $this->onQueue('ids-processing');
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        Log::info('Processing access log', [
            'ip' => $this->logData['ip'],
            'uri' => $this->logData['uri']['path'] ?? 'unknown',
            'method' => $this->logData['method'] ?? 'unknown',
        ]);

        $detections = [];

        // Phase 2.1: Signature Detection
        $signatureEngine = app(\App\Services\Detection\SignatureEngine::class);
        if ($signatureResult = $signatureEngine->analyze($this->logData)) {
            $detections['signature'] = $signatureResult;
            Log::warning('Signature detected', $signatureResult);
        }

        // Phase 2.2: Anomaly Detection
        $anomalyEngine = app(\App\Services\Detection\AnomalyEngine::class);
        if ($anomalyResult = $anomalyEngine->analyze($this->logData)) {
            $detections['anomaly'] = $anomalyResult;
            Log::warning('Anomaly detected', $anomalyResult);
        }

        // Phase 2.3: Behavior Analysis
        $behaviorEngine = app(\App\Services\Detection\BehaviorEngine::class);
        if ($behaviorResult = $behaviorEngine->analyze($this->logData)) {
            $detections['behavior'] = $behaviorResult;
            Log::warning('Malicious behavior detected', $behaviorResult);
        }

        // If any threats detected, trigger alert (Phase 3)
        if (!empty($detections)) {
            $this->handleThreatDetection($detections);
        }

        Log::debug('Access log processed successfully', $this->logData);
    }

    /**
     * Handle detected threats
     */
    private function handleThreatDetection(array $detections): void
    {
        // Determine overall severity
        $severity = 'low';
        
        if (isset($detections['signature'])) {
            $severity = $detections['signature']['severity'];
        } elseif (isset($detections['anomaly'])) {
            $severity = $detections['anomaly']['severity'];
        }

        $ip = $this->logData['ip'] ?? 'unknown';

        Log::warning('Threat detected', [
            'ip' => $ip,
            'severity' => $severity,
            'detections' => array_keys($detections),
        ]);

        // Phase 3: Generate alert and sync to WAF Hub
        try {
            $alertService = app(\App\Services\AlertService::class);
            
            // Check rate limiting to prevent alert flooding
            $category = $detections['signature']['category'] ?? 'anomaly';
            if (!$alertService->shouldRateLimit($ip, $category)) {
                $alert = $alertService->createAlert($this->logData, $detections);
                Log::info('Alert created and synced', ['alert_id' => $alert['source_ip']]);
                
                // Send notifications (Phase 3.3)
                $notificationService = app(\App\Services\NotificationService::class);
                $notificationService->sendAlertNotification($alert);
            } else {
                Log::info('Alert rate-limited', ['ip' => $ip, 'category' => $category]);
            }
        } catch (\Exception $e) {
            Log::error('Failed to create alert', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);
        }

        // Phase 4: Trigger blocking if severity is critical/high
        if (in_array($severity, ['critical', 'high'])) {
            try {
                $blockingService = app(\App\Services\BlockingService::class);
                
                $reason = $this->formatBlockReason($detections);
                $blocked = $blockingService->blockIP($ip, $reason, $severity);
                
                if ($blocked) {
                    Log::warning('IP automatically blocked', [
                        'ip' => $ip,
                        'severity' => $severity,
                        'reason' => $reason,
                    ]);
                }
            } catch (\Exception $e) {
                Log::error('Failed to block IP', [
                    'ip' => $ip,
                    'error' => $e->getMessage(),
                ]);
            }
        }
    }

    /**
     * Format block reason from detections
     */
    private function formatBlockReason(array $detections): string
    {
        if (isset($detections['signature'])) {
            return sprintf(
                "Attack detected: %s (%s)",
                $detections['signature']['signature_name'] ?? 'Unknown',
                $detections['signature']['category'] ?? 'unknown'
            );
        }

        if (isset($detections['anomaly'])) {
            $types = [];
            foreach ($detections['anomaly']['anomalies'] ?? [] as $anomaly) {
                $types[] = $anomaly['type'] ?? 'unknown';
            }
            return "Anomalies detected: " . implode(', ', $types);
        }

        return "Security threat detected";
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error('Failed to process access log', [
            'log_data' => $this->logData,
            'error' => $exception->getMessage(),
        ]);
    }
}
