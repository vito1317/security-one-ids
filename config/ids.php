<?php

return [
    /*
    |--------------------------------------------------------------------------
    | IDS/IPS Configuration
    |--------------------------------------------------------------------------
    */

    /**
     * Nginx Access Log Path
     */
    'nginx_log_path' => env('IDS_NGINX_LOG_PATH', '/var/log/nginx/access.log'),

    /**
     * Log Monitoring Settings
     */
    'log_monitor' => [
        'enabled' => env('IDS_LOG_MONITOR_ENABLED', true),
        'batch_size' => env('IDS_LOG_BATCH_SIZE', 100),
        'check_interval' => env('IDS_LOG_CHECK_INTERVAL', 5), // seconds
    ],

    /**
     * Queue Settings
     */
    'queue' => [
        'connection' => env('IDS_QUEUE_CONNECTION', 'database'),
        'name' => env('IDS_QUEUE_NAME', 'ids-processing'),
    ],

    /**
     * Detection Settings (placeholder for Phase 2)
     */
    'detection' => [
        'signature_enabled' => true,
        'anomaly_enabled' => true,
        'behavior_enabled' => true,
    ],

    /**
     * Blocking Settings (placeholder for Phase 4)
     */
    'blocking' => [
        'enabled' => env('IDS_BLOCKING_ENABLED', false),
        'mode' => env('IDS_BLOCKING_MODE', 'hybrid'), // 'waf', 'iptables', 'hybrid'
        'auto_unblock_after' => env('IDS_AUTO_UNBLOCK_AFTER', 3600), // seconds
    ],

    /**
     * Alert Settings (placeholder for Phase 3)
     */
    'alerts' => [
        'email_enabled' => env('IDS_ALERT_EMAIL_ENABLED', false),
        'email_to' => env('IDS_ALERT_EMAIL_TO', 'admin@example.com'),
        'webhook_enabled' => env('IDS_ALERT_WEBHOOK_ENABLED', false),
        'webhook_url' => env('IDS_ALERT_WEBHOOK_URL'),
    ],
];
