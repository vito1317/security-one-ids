<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class Heartbeat extends Command
{
    protected $signature = 'waf:heartbeat
        {--daemon : Run continuously in daemon mode}
        {--interval=60 : Heartbeat interval in seconds (daemon mode)}';
    protected $description = 'Send heartbeat to WAF Hub (standalone, non-blocking)';

    public function handle(WafSyncService $wafSync): int
    {
        if ($this->option('daemon')) {
            return $this->runDaemon($wafSync);
        }

        return $this->runOnce($wafSync);
    }

    /**
     * Send a single heartbeat
     */
    private function runOnce(WafSyncService $wafSync): int
    {
        if ($wafSync->heartbeat()) {
            Log::debug('[Heartbeat] OK');
            return 0;
        }

        Log::warning('[Heartbeat] Failed');
        return 1;
    }

    /**
     * Run heartbeat continuously as a daemon
     */
    private function runDaemon(WafSyncService $wafSync): int
    {
        $interval = max(5, min(300, (int) $this->option('interval')));
        Log::info("[Heartbeat] Daemon started, interval: {$interval}s");

        while (true) {
            try {
                $this->runOnce($wafSync);
            } catch (\Exception $e) {
                Log::error('[Heartbeat] Error: ' . $e->getMessage());
            }

            // Re-read interval from Hub config
            $config = $wafSync->getWafConfig();
            $hubInterval = $config['heartbeat_interval'] ?? null;
            if ($hubInterval && $hubInterval >= 5 && $hubInterval <= 300) {
                $interval = (int) $hubInterval;
            }

            sleep($interval);
        }
    }
}
