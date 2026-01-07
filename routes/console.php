<?php

use App\Services\WafSyncService;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// Send heartbeat to WAF every minute
Schedule::call(function (WafSyncService $wafSync) {
    $wafSync->heartbeat();
})->everyMinute();
