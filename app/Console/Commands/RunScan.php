<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class RunScan extends Command
{
    protected $signature = 'ids:scan';
    protected $description = 'Run ClamAV scan in background';

    public function handle(): int
    {
        try {
            Log::info('Background scan started');
            
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::warning('ClamAV not installed, cannot perform scan');
                return 1;
            }
            
            // Send initial "scanning" status to WAF Hub
            $clamav->reportToHub(['scan_status' => 'scanning']);
            
            // Use platform-specific scan paths
            $platform = PHP_OS_FAMILY === 'Darwin' ? 'macos' : 'linux';
            
            if ($platform === 'macos') {
                $scanPaths = ['/Users', '/Applications', '/tmp'];
            } else {
                $scanPaths = ['/home', '/var/www', '/tmp'];
            }
            
            Log::info("Starting ClamAV scan on {$platform}", ['paths' => $scanPaths]);
            
            $totalPaths = count($scanPaths);
            $completedPaths = 0;
            
            $allResults = [
                'last_scan' => now()->toDateTimeString(),
                'infected_files' => 0,
                'scanned_files' => 0,
                'threats' => [],
                'scan_status' => 'scanning',
            ];
            
            foreach ($scanPaths as $path) {
                if (is_dir($path)) {
                    $completedPaths++;
                    Log::info("Scanning directory ({$completedPaths}/{$totalPaths}): {$path}");
                    
                    $result = $clamav->scan($path);
                    
                    if ($result['success']) {
                        $allResults['scanned_files'] += $result['scanned_files'] ?? 0;
                        $allResults['infected_files'] += $result['infected_files'] ?? 0;
                        $allResults['threats'] = array_merge($allResults['threats'], $result['threats'] ?? []);
                    }
                    
                    // Report progress after each directory (still scanning)
                    $progressResults = $allResults;
                    $progressResults['scan_status'] = 'scanning';
                    $progressResults['scan_progress'] = "{$completedPaths}/{$totalPaths} directories";
                    $clamav->reportToHub($progressResults);
                    
                    Log::info("Progress: {$completedPaths}/{$totalPaths} directories completed", [
                        'path' => $path,
                        'scanned_files' => $allResults['scanned_files'],
                        'infected_files' => $allResults['infected_files'],
                    ]);
                } else {
                    $completedPaths++;
                    Log::info("Skipping non-existent directory ({$completedPaths}/{$totalPaths}): {$path}");
                }
            }
            
            Log::info('ClamAV scan completed', [
                'scanned_files' => $allResults['scanned_files'],
                'infected_files' => $allResults['infected_files'],
            ]);
            
            // Report final results with idle status
            $allResults['scan_status'] = 'idle';
            $allResults['status'] = $allResults['infected_files'] > 0 ? 'warning' : 'healthy';
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
