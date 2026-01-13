<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class RunScan extends Command
{
    protected $signature = 'ids:scan {--type=quick : Scan type (quick or full)}';
    protected $description = 'Run ClamAV scan in background';

    public function handle(): int
    {
        try {
            $scanType = $this->option('type') ?: 'quick';
            Log::info("Background scan started (type: {$scanType})");
            
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::warning('ClamAV not installed, cannot perform scan');
                return 1;
            }
            
            // Send initial "scanning" status to WAF Hub
            $clamav->reportToHub(['scan_status' => 'scanning']);
            
            // Use platform-specific scan paths based on scan type
            $platform = PHP_OS_FAMILY === 'Darwin' ? 'macos' : 'linux';
            
            if ($scanType === 'full') {
                // Full scan - more comprehensive directories
                if ($platform === 'macos') {
                    $scanPaths = ['/Users', '/Applications', '/tmp', '/Library'];
                } else {
                    $scanPaths = ['/home', '/var/www', '/var/log', '/tmp', '/opt', '/etc'];
                }
            } else {
                // Quick scan - only critical areas
                if ($platform === 'macos') {
                    $scanPaths = ['/tmp', '/Users/' . get_current_user() . '/Downloads'];
                } else {
                    $scanPaths = ['/tmp', '/var/www', '/home/' . get_current_user() . '/Downloads'];
                }
            }
            
            Log::info("Starting ClamAV {$scanType} scan on {$platform}", ['paths' => $scanPaths]);
            
            $totalPaths = count($scanPaths);
            $completedPaths = 0;
            
            $allResults = [
                'last_scan' => now()->toDateTimeString(),
                'infected_files' => 0,
                'scanned_files' => 0,
                'threats' => [],
                'scan_status' => 'scanning',
            ];
            
            foreach ($scanPaths as $index => $path) {
                if (is_dir($path)) {
                    $currentPath = $index + 1;
                    Log::info("Scanning directory ({$currentPath}/{$totalPaths}): {$path}");
                    
                    // Report progress BEFORE starting scan (so user sees current directory)
                    $clamav->reportToHub([
                        'scan_status' => 'scanning',
                        'scan_progress' => "掃描中: {$path} ({$currentPath}/{$totalPaths})",
                        'scanned_files' => $allResults['scanned_files'],
                        'infected_files' => $allResults['infected_files'],
                    ]);
                    
                    $result = $clamav->scan($path);
                    $completedPaths++;
                    
                    if ($result['success']) {
                        $allResults['scanned_files'] += $result['scanned_files'] ?? 0;
                        $allResults['infected_files'] += $result['infected_files'] ?? 0;
                        $allResults['threats'] = array_merge($allResults['threats'], $result['threats'] ?? []);
                    }
                    
                    Log::info("Directory completed: {$path}", [
                        'scanned_files' => $allResults['scanned_files'],
                        'infected_files' => $allResults['infected_files'],
                    ]);
                } else {
                    $completedPaths++;
                    Log::info("Skipping non-existent directory: {$path}");
                }
            }
            
            Log::info('ClamAV scan completed', [
                'scanned_files' => $allResults['scanned_files'],
                'infected_files' => $allResults['infected_files'],
            ]);
            
            // Report final results with idle status
            $allResults['scan_status'] = 'idle';
            $allResults['scan_progress'] = null;
            $allResults['last_scan'] = now()->toDateTimeString();
            $allResults['status'] = $allResults['infected_files'] > 0 ? 'warning' : 'healthy';
            
            Log::info('Sending final scan report', [
                'last_scan' => $allResults['last_scan'],
                'scanned_files' => $allResults['scanned_files'],
                'infected_files' => $allResults['infected_files'],
            ]);
            
            $clamav->reportToHub($allResults);
            
            $this->info('Scan completed successfully');
            return 0;
            
        } catch (\Exception $e) {
            Log::error('Background scan failed: ' . $e->getMessage());
            
            try {
                $clamav = app(\App\Services\ClamavService::class);
                $clamav->reportToHub(['scan_status' => 'idle', 'status' => 'error', 'error_message' => $e->getMessage()]);
            } catch (\Exception $ex) {
                // Ignore
            }
            
            return 1;
        }
    }
}
