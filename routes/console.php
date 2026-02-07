<?php

use App\Services\WafSyncService;
use App\Services\ClamavService;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Dynamic heartbeat command - checks scan status to determine interval
Artisan::command('waf:heartbeat {--daemon : Run continuously with dynamic interval}', function (WafSyncService $wafSync) {
    if ($this->option('daemon')) {
        // Run as daemon with dynamic interval from WAF Hub config
        $this->info('Starting heartbeat daemon...');
        while (true) {
            $wafSync->heartbeat();
            
            // Read interval from config (updated by syncConfigFromHub)
            $configPath = storage_path('app/waf_config.json');
            $interval = 60; // Default
            if (file_exists($configPath)) {
                $config = json_decode(file_get_contents($configPath), true) ?: [];
                $interval = (int) ($config['heartbeat_interval'] ?? 60);
                $interval = max(10, min(300, $interval)); // Clamp 10-300
            }
            
            $this->info("Next heartbeat in {$interval} seconds...");
            sleep($interval);
        }
    } else {
        // Single heartbeat
        $wafSync->heartbeat();
    }
})->purpose('Send heartbeat to WAF Hub');

// Fast heartbeat during scanning
Artisan::command('waf:heartbeat-if-scanning', function (WafSyncService $wafSync, ClamavService $clamav) {
    if ($clamav->isScanRunning()) {
        $wafSync->heartbeat();
    }
})->purpose('Send heartbeat only if scan is running');

// Dynamic heartbeat command that respects heartbeat_interval from Hub config
Artisan::command('waf:heartbeat-dynamic', function (WafSyncService $wafSync) {
    // Check configured interval from Hub config
    $configPath = storage_path('app/waf_config.json');
    $interval = 60; // Default
    if (file_exists($configPath)) {
        $config = json_decode(file_get_contents($configPath), true) ?: [];
        $interval = (int) ($config['heartbeat_interval'] ?? 60);
        $interval = max(10, min(300, $interval)); // Clamp 10-300s
    }

    // Check if enough time has passed since last heartbeat
    $lastBeatFile = storage_path('app/last_heartbeat.txt');
    $lastBeat = file_exists($lastBeatFile) ? (int) file_get_contents($lastBeatFile) : 0;
    $elapsed = time() - $lastBeat;

    if ($elapsed >= $interval) {
        $wafSync->heartbeat();
        file_put_contents($lastBeatFile, time());
    }
})->purpose('Send heartbeat respecting configured interval');

// Run heartbeat check every 10 seconds (actual interval controlled by heartbeat_interval config)
Schedule::command('waf:heartbeat-dynamic')->everyTenSeconds();

// Fast heartbeat during scanning - every 10 seconds
Schedule::command('waf:heartbeat-if-scanning')->everyTenSeconds();

// Run security scan every 5 minutes and report threats to WAF Hub
Schedule::command('desktop:scan --full')
    ->everyFiveMinutes()
    ->runInBackground()
    ->withoutOverlapping();
