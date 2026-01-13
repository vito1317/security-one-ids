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
            
            // Send "scanning" status to WAF Hub
            $clamav->reportToHub(['scan_status' => 'scanning']);
            
            // Use platform-specific scan paths
            $platform = PHP_OS_FAMILY === 'Darwin' ? 'macos' : 'linux';
            
            if ($platform === 'macos') {
                $scanPaths = ['/Users', '/Applications', '/tmp'];
            } else {
                $scanPaths = ['/home', '/var/www', '/tmp'];
            }
            
            Log::info("Starting ClamAV scan on {$platform}", ['paths' => $scanPaths]);
            
            $allResults = [
                'last_scan' => now()->toDateTimeString(),
                'infected_files' => 0,
                'scanned_files' => 0,
                'threats' => [],
                'scan_status' => 'scanning',
            ];
            
            foreach ($scanPaths as $path) {
                if (is_dir($path)) {
                    Log::info("Scanning directory: {$path}");
                    $result = $clamav->scan($path);
                    
                    if ($result['success']) {
                        $allResults['scanned_files'] += $result['scanned_files'] ?? 0;
                        $allResults['infected_files'] += $result['infected_files'] ?? 0;
                        $allResults['threats'] = array_merge($allResults['threats'], $result['threats'] ?? []);
                    }
                }
            }
            
            Log::info('ClamAV scan completed', [
                'scanned_files' => $allResults['scanned_files'],
                'infected_files' => $allResults['infected_files'],
            ]);
            
            // Report completed results with idle status
            $allResults['scan_status'] = 'idle';
            $clamav->reportToHub($allResults);
            
            $this->info('Scan completed successfully');
            return 0;
            
        } catch (\Exception $e) {
            Log::error('Background scan failed: ' . $e->getMessage());
            
            try {
                $clamav = app(\App\Services\ClamavService::class);
                $clamav->reportToHub(['scan_status' => 'idle']);
            } catch (\Exception $ex) {
                // Ignore
            }
            
            return 1;
        }
    }
}
