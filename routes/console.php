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

// Send heartbeat to WAF every minute (normal mode)
Schedule::command('waf:heartbeat')->everyMinute();

// Fast heartbeat during scanning - every 10 seconds
// This runs continuously but only sends if scan is in progress
Schedule::call(function (WafSyncService $wafSync, ClamavService $clamav) {
    if ($clamav->isScanRunning()) {
        $wafSync->heartbeat();
    }
})->everyTenSeconds()->runInBackground();

// Run security scan every 5 minutes and report threats to WAF Hub
Schedule::command('desktop:scan --full')
    ->everyFiveMinutes()
    ->runInBackground()
    ->withoutOverlapping();
