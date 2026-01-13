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
            $this->info("Background scan started (type: {$scanType})");
            
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::warning('ClamAV not installed, cannot perform scan');
                return 1;
            }
            
            // Send initial "scanning" status to WAF Hub
            $this->info("Sending initial 'scanning' status to WAF Hub...");
            $result = $clamav->reportToHub(['scan_status' => 'scanning']);
            $this->info("reportToHub result: " . ($result ? 'success' : 'failed'));
            
            // Use platform-specific scan paths based on scan type
            $platform = PHP_OS_FAMILY === 'Darwin' ? 'macos' : 'linux';
            
            if ($scanType === 'full') {
                // Full scan - more comprehensive directories
                if ($platform === 'macos') {
                    $scanPaths = ['/Users', '/Applications', '/tmp', '/Library'];
                } else {
                    // Docker container: use mounted host directories if available
                    $scanPaths = [];
                    $hostMounts = [
                        '/mnt/host-home' => '/mnt/host-home',     // Host /home
                        '/mnt/host-www' => '/mnt/host-www',       // Host /var/www
                        '/mnt/host-opt' => '/mnt/host-opt',       // Host /opt
                        '/mnt/host-tmp' => '/mnt/host-tmp',       // Host /tmp
                    ];
                    foreach ($hostMounts as $mount => $path) {
                        if (is_dir($mount)) {
                            $scanPaths[] = $path;
                        }
                    }
                    // Fallback to container paths if no host mounts
                    if (empty($scanPaths)) {
                        $scanPaths = ['/home', '/var/www', '/var/log', '/tmp', '/opt', '/etc'];
                    }
                }
            } else {
                // Quick scan - only critical areas
                if ($platform === 'macos') {
                    // Use /private/tmp (actual tmp location) and scan existing user Downloads
                    $scanPaths = ['/private/tmp'];
                    
                    // Find actual user's Downloads folder
                    $usersDir = '/Users';
                    if (is_dir($usersDir)) {
                        $users = array_diff(scandir($usersDir), ['.', '..', 'Shared', '.localized']);
                        foreach ($users as $user) {
                            $downloads = "{$usersDir}/{$user}/Downloads";
                            if (is_dir($downloads) && is_readable($downloads)) {
                                $scanPaths[] = $downloads;
                                break; // Only scan first found user
                            }
                        }
                    }
                } else {
                    // Docker container: use mounted host directories if available
                    if (is_dir('/mnt/host-tmp') || is_dir('/mnt/host-www')) {
                        $scanPaths = [];
                        if (is_dir('/mnt/host-tmp')) $scanPaths[] = '/mnt/host-tmp';
                        if (is_dir('/mnt/host-www')) $scanPaths[] = '/mnt/host-www';
                    } else {
                        $scanPaths = ['/tmp', '/var/www', '/home/' . get_current_user() . '/Downloads'];
                    }
                }
            }
            
            Log::info("Starting ClamAV {$scanType} scan on {$platform}", ['paths' => $scanPaths]);
            
            $totalPaths = count($scanPaths);
            $completedPaths = 0;
            
            // Save scan paths to cache for getScanProgress to calculate index
            $pathsFile = storage_path('app/scan_paths.json');
            file_put_contents($pathsFile, json_encode(['paths' => $scanPaths]));
            
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
                    
                    // Translate Docker container paths to host paths for display
                    $displayPath = $clamav->translateDockerPath($path);
                    
                    // Save progress to cache file for heartbeat to read
                    $progressText = "掃描中: {$displayPath} ({$currentPath}/{$totalPaths})";
                    $clamav->saveScanProgress($progressText);
                    
                    // Report progress BEFORE starting scan (so user sees current directory)
                    $clamav->reportToHub([
                        'scan_status' => 'scanning',
                        'scan_progress' => $progressText,
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
            $this->info("Scan completed: {$allResults['scanned_files']} files, {$allResults['infected_files']} infected");
            
            // Report final results with idle status
            $allResults['scan_status'] = 'idle';
            $allResults['scan_progress'] = null;
            $allResults['last_scan'] = now()->toDateTimeString();
            $allResults['status'] = $allResults['infected_files'] > 0 ? 'warning' : 'healthy';
            $allResults['scan_completed'] = true;  // Explicit flag to tell WAF Hub to accept idle
            
            Log::info('Sending final scan report', [
                'last_scan' => $allResults['last_scan'],
                'scanned_files' => $allResults['scanned_files'],
                'infected_files' => $allResults['infected_files'],
            ]);
            
            // Clear progress cache before final report
            $clamav->clearScanProgress();
            
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
