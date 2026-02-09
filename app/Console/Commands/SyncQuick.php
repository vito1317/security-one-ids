<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class SyncQuick extends Command
{
    protected $signature = 'ids:sync-quick';
    protected $description = 'Run quick sync tasks (rules, alerts, blocked IPs)';

    public function handle(WafSyncService $wafSync): int
    {
        Log::debug('[SyncQuick] Starting quick sync tasks...');

        try {
            $wafSync->runQuickSync();
            Log::debug('[SyncQuick] Completed');
        } catch (\Exception $e) {
            Log::error('[SyncQuick] Error: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }
}
