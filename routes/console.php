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
Artisan::command('waf:heartbeat', function (WafSyncService $wafSync) {
    $wafSync->heartbeat();
})->purpose('Send heartbeat to WAF Hub');

// Fast heartbeat during scanning
Artisan::command('waf:heartbeat-if-scanning', function (WafSyncService $wafSync, ClamavService $clamav) {
    if ($clamav->isScanRunning()) {
        $wafSync->heartbeat();
    }
})->purpose('Send heartbeat only if scan is running');

// Send heartbeat to WAF every minute (normal mode)
Schedule::command('waf:heartbeat')->everyMinute();

// Fast heartbeat during scanning - every 10 seconds
Schedule::command('waf:heartbeat-if-scanning')->everyTenSeconds();

// Run security scan every 5 minutes and report threats to WAF Hub
Schedule::command('desktop:scan --full')
    ->everyFiveMinutes()
    ->runInBackground()
    ->withoutOverlapping();
