<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class SyncSnort extends Command
{
    protected $signature = 'ids:sync-snort';
    protected $description = 'Deprecated — redirects to Suricata management tasks';

    public function handle(WafSyncService $wafSync): int
    {
        Log::debug('[SyncSnort] Deprecated — redirecting to Suricata sync');

        try {
            $wafSync->runSuricataSync();
            Log::debug('[SyncSnort] Completed (via Suricata)');
        } catch (\Exception $e) {
            Log::error('[SyncSnort] Error: ' . $e->getMessage());
            return 1;
        }

        return 0;
    }
}
