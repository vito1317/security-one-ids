<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class SyncSuricata extends Command
{
    protected $signature = 'ids:sync-suricata';
    protected $description = 'Run Suricata management tasks (install, start, rules sync, auto-update)';

    public function handle(WafSyncService $wafSync): int
    {
        Log::debug('[SyncSuricata] Starting Suricata management tasks...');

        try {
            $wafSync->runSuricataSync();
            Log::debug('[SyncSuricata] Completed');
        } catch (\Exception $e) {
            Log::error('[SyncSuricata] Error: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }
}
