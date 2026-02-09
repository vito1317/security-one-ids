<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class SyncSnort extends Command
{
    protected $signature = 'ids:sync-snort';
    protected $description = 'Run Snort management tasks (install, Npcap, start, auto-update)';

    public function handle(WafSyncService $wafSync): int
    {
        Log::debug('[SyncSnort] Starting Snort management tasks...');

        try {
            $wafSync->runSnortSync();
            Log::debug('[SyncSnort] Completed');
        } catch (\Exception $e) {
            Log::error('[SyncSnort] Error: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }
}
