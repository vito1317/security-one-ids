<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;

class SyncToWaf extends Command
{
    protected $signature = 'waf:sync 
        {--register : Force registration}
        {--once : Run once and exit (for debugging)}
        {--debug : Show debug information}';
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
                
                // Upload signatures immediately after registration
                $this->info('Uploading signatures after registration...');
                $uploaded = $wafSync->uploadSignatures();
                $this->info("✓ Uploaded {$uploaded} signatures to WAF");
            } else {
                $this->error('✗ Failed to register with WAF');
                return 1;
            }
        }

        // Debug output if requested
        if ($this->option('debug')) {
            $this->info('=== DEBUG INFO ===');
            $this->info('PHP_OS_FAMILY: ' . PHP_OS_FAMILY);
            $this->info('PHP_OS: ' . PHP_OS);
            $this->info('php_uname: ' . php_uname('s'));
            
            // Test network stats directly
            $this->info('Testing network stats collection...');
            if (PHP_OS_FAMILY === 'Darwin') {
                $this->info('Detected macOS, testing netstat...');
                $output = shell_exec('netstat -I en0 -b 2>&1');
                $this->info("netstat -I en0 -b output:\n" . $output);
                
                // Parse and show result
                $lines = explode("\n", trim($output ?? ''));
                if (isset($lines[1])) {
                    $parts = preg_split('/\s+/', trim($lines[1]));
                    $this->info('Parsed columns: ' . count($parts));
                    if (count($parts) >= 10) {
                        $this->info("Ibytes (col 6): " . ($parts[6] ?? 'N/A'));
                        $this->info("Obytes (col 9): " . ($parts[9] ?? 'N/A'));
                    }
                }
            } elseif (PHP_OS_FAMILY === 'Windows') {
                $this->info('Detected Windows');
            } else {
                $this->info('Detected Linux');
            }
            $this->info('=== END DEBUG ===');
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
