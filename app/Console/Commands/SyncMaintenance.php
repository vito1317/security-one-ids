<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class SyncMaintenance extends Command
{
    protected $signature = 'ids:sync-maintenance';
    protected $description = 'Run maintenance tasks (ClamAV, updates, definitions, scan, system signals)';

    public function handle(WafSyncService $wafSync): int
    {
        Log::debug('[SyncMaintenance] Starting maintenance tasks...');

        try {
            $wafSync->runMaintenanceSync();
            Log::debug('[SyncMaintenance] Completed');
        } catch (\Exception $e) {
            Log::error('[SyncMaintenance] Error: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }
}
