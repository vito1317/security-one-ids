<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;

/**
 * Notification Service
 * 
 * Sends notifications via multiple channels
 */
class NotificationService
{
    /**
     * Send notification for alert
     *
     * @param array $alert Alert data
     * @return void
     */
    public function sendAlertNotification(array $alert): void
    {
        $severity = $alert['severity'] ?? 'low';
        $category = $alert['category'] ?? 'unknown';
        $ip = $alert['source_ip'] ?? 'unknown';

        // Only notify for high/critical
        if (!in_array($severity, ['critical', 'high'])) {
            return;
        }

        // Email notification
        if (config('ids.alerts.email_enabled')) {
            $this->sendEmail($alert);
        }

        // Webhook notification
        if (config('ids.alerts.webhook_enabled')) {
            $this->sendWebhook($alert);
        }

        // Slack notification
        if (config('ids.alerts.slack_enabled')) {
            $this->sendSlack($alert);
        }

        // Discord notification
        if (config('ids.alerts.discord_enabled')) {
            $this->sendDiscord($alert);
        }
    }

    /**
     * Send email notification
     */
    private function sendEmail(array $alert): void
    {
        try {
            $to = config('ids.alerts.email_to');
            $subject = sprintf(
                '[%s] Security Alert: %s from %s',
                strtoupper($alert['severity']),
                $alert['category'],
                $alert['source_ip']
            );

            $body = $this->formatEmailBody($alert);

            Mail::raw($body, function ($message) use ($to, $subject) {
                $message->to($to)
                    ->subject($subject);
            });

            Log::info('Email notification sent', ['to' => $to]);

        } catch (\Exception $e) {
            Log::error('Failed to send email notification', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Send webhook notification
     */
    private function sendWebhook(array $alert): void
    {
        try {
            $url = config('ids.alerts.webhook_url');
            if (empty($url)) {
                return;
            }

            $response = Http::timeout(10)->post($url, [
                'type' => 'security_alert',
                'severity' => $alert['severity'],
                'alert' => $alert,
                'timestamp' => now()->toIso8601String(),
            ]);

            if ($response->successful()) {
                Log::info('Webhook notification sent', ['url' => $url]);
            } else {
                Log::error('Webhook notification failed', [
                    'url' => $url,
                    'status' => $response->status(),
                ]);
            }

        } catch (\Exception $e) {
            Log::error('Failed to send webhook notification', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Send Slack notification
     */
    private function sendSlack(array $alert): void
    {
        try {
            $webhookUrl = config('ids.alerts.slack_webhook_url');
            if (empty($webhookUrl)) {
                return;
            }

            $color = match ($alert['severity']) {
                'critical' => 'danger',
                'high' => 'warning',
                'medium' => '#ffaa00',
                default => 'good',
            };

            $response = Http::timeout(10)->post($webhookUrl, [
                'attachments' => [[
                    'color' => $color,
                    'title' => sprintf('🚨 Security Alert: %s', strtoupper($alert['severity'])),
                    'text' => sprintf(
                        "*IP:* `%s`\n*Category:* %s\n*URI:* %s\n*Details:* %s",
                        $alert['source_ip'],
                        $alert['category'],
                        $alert['uri'] ?? 'N/A',
                        substr($alert['detections'] ?? '', 0, 200)
                    ),
                    'footer' => 'Security One IDS',
                    'ts' => time(),
                ]],
            ]);

            if ($response->successful()) {
                Log::info('Slack notification sent');
            }

        } catch (\Exception $e) {
            Log::error('Failed to send Slack notification', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Send Discord notification
     */
    private function sendDiscord(array $alert): void
    {
        try {
            $webhookUrl = config('ids.alerts.discord_webhook_url');
            if (empty($webhookUrl)) {
                return;
            }

            $color = match ($alert['severity']) {
                'critical' => 0xFF0000, // Red
                'high' => 0xFF6600,     // Orange
                'medium' => 0xFFAA00,   // Yellow
                default => 0x00FF00,    // Green
            };

            $response = Http::timeout(10)->post($webhookUrl, [
                'embeds' => [[
                    'title' => '🚨 Security Alert',
                    'color' => $color,
                    'fields' => [
                        ['name' => 'Severity', 'value' => strtoupper($alert['severity']), 'inline' => true],
                        ['name' => 'Category', 'value' => $alert['category'], 'inline' => true],
                        ['name' => 'Source IP', 'value' => '`' . $alert['source_ip'] . '`', 'inline' => true],
                        ['name' => 'URI', 'value' => $alert['uri'] ?? 'N/A', 'inline' => false],
                        ['name' => 'Details', 'value' => substr($alert['detections'] ?? '', 0, 200), 'inline' => false],
                    ],
                    'footer' => ['text' => 'Security One IDS'],
                    'timestamp' => now()->toIso8601String(),
                ]],
            ]);

            if ($response->successful()) {
                Log::info('Discord notification sent');
            }

        } catch (\Exception $e) {
            Log::error('Failed to send Discord notification', [
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Format email body
     */
    private function formatEmailBody(array $alert): string
    {
        return sprintf(
            "Security Alert Detected\n" .
            "====================\n\n" .
            "Severity: %s\n" .
            "Category: %s\n" .
            "Source IP: %s\n" .
            "URI: %s\n" .
            "Method: %s\n" .
            "User-Agent: %s\n" .
            "Timestamp: %s\n\n" .
            "Detection Details:\n" .
            "%s\n\n" .
            "Raw Log:\n" .
            "%s\n",
            strtoupper($alert['severity']),
            $alert['category'],
            $alert['source_ip'],
            $alert['uri'] ?? 'N/A',
            $alert['method'] ?? 'N/A',
            substr($alert['user_agent'] ?? '', 0, 100),
            $alert['timestamp'] ?? now()->toDateTimeString(),
            $alert['detections'] ?? 'N/A',
            $alert['raw_log'] ?? 'N/A'
        );
    }

    /**
     * Send test notification
     */
    public function sendTestNotification(): array
    {
        $results = [];

        $testAlert = [
            'severity' => 'high',
            'category' => 'test',
            'source_ip' => '192.168.1.100',
            'uri' => '/test',
            'method' => 'GET',
            'user_agent' => 'Test Agent',
            'timestamp' => now()->toDateTimeString(),
            'detections' => 'This is a test alert',
            'raw_log' => 'Test log entry',
        ];

        if (config('ids.alerts.email_enabled')) {
            try {
                $this->sendEmail($testAlert);
                $results['email'] = 'sent';
            } catch (\Exception $e) {
                $results['email'] = 'failed: ' . $e->getMessage();
            }
        }

        if (config('ids.alerts.webhook_enabled')) {
            try {
                $this->sendWebhook($testAlert);
                $results['webhook'] = 'sent';
            } catch (\Exception $e) {
                $results['webhook'] = 'failed: ' . $e->getMessage();
            }
        }

        if (config('ids.alerts.slack_enabled')) {
            try {
                $this->sendSlack($testAlert);
                $results['slack'] = 'sent';
            } catch (\Exception $e) {
                $results['slack'] = 'failed: ' . $e->getMessage();
            }
        }

        if (config('ids.alerts.discord_enabled')) {
            try {
                $this->sendDiscord($testAlert);
                $results['discord'] = 'sent';
            } catch (\Exception $e) {
                $results['discord'] = 'failed: ' . $e->getMessage();
            }
        }

        return $results;
    }
}
