<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;

class SyncToWaf extends Command
{
    protected $signature = 'waf:sync {--register : Force registration}';
    protected $description = 'Sync this IDS Agent with the central WAF';

    public function handle(WafSyncService $wafSync): int
    {
        $this->info('Starting WAF synchronization...');

        // Register if first time or forced
        if ($this->option('register') || !cache()->has('waf_registered')) {
            $this->info('Registering with WAF...');
            if ($wafSync->register()) {
                cache()->put('waf_registered', true, now()->addDays(30));
                $this->info('✓ Successfully registered with WAF');
            } else {
                $this->error('✗ Failed to register with WAF');
                return 1;
            }
        }

        // Send heartbeat
        $this->info('Sending heartbeat...');
        if ($wafSync->heartbeat()) {
            $this->info('✓ Heartbeat sent');
        } else {
            $this->warn('✗ Heartbeat failed');
        }

        // Fetch latest rules and sync to database
        $this->info('Fetching rules from WAF...');
        $rules = $wafSync->fetchRules();
        if ($rules && isset($rules['rules']) && count($rules['rules']) > 0) {
            $count = count($rules['rules']);
            $this->info("✓ Received {$count} rules from WAF");
            
            // Sync rules to local database
            $synced = $wafSync->syncRulesToDatabase($rules['rules']);
            $this->info("✓ Synced {$synced} rules to local database");
            
            // Also cache for quick access
            cache()->put('ids_rules', $rules['rules'], now()->addHour());
        } else {
            $this->warn('No rules received from WAF');
        }

        // Upload local signatures to WAF Hub
        $this->info('Uploading local signatures to WAF...');
        $uploaded = $wafSync->uploadSignatures();
        if ($uploaded > 0) {
            $this->info("✓ Uploaded {$uploaded} signatures to WAF");
        } else {
            $this->warn('No signatures uploaded to WAF');
        }

        $this->info('Sync completed!');
        return 0;
    }
}
