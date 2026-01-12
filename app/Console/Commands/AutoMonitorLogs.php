<?php

namespace App\Console\Commands;

use App\Jobs\ProcessAccessLog;
use App\Services\LogCollectorService;
use App\Services\LogDiscoveryService;
use Illuminate\Console\Command;

/**
 * Auto Monitor All Logs Command
 * 
 * Automatically discovers and monitors all web server logs on the system
 */
class AutoMonitorLogs extends Command
{
    protected $signature = 'ids:auto-monitor 
                            {--interval=5 : Seconds between checks}
                            {--add-path= : Add a custom log path to monitor}
                            {--list : List discovered log files}';

    protected $description = 'Auto-discover and monitor all web server logs (Nginx, Apache)';

    private array $filePositions = [];

    public function handle(LogCollectorService $collector, LogDiscoveryService $discovery): int
    {
        // Handle add-path option
        if ($path = $this->option('add-path')) {
            if ($discovery->addCustomPath($path)) {
                $this->info("✓ Added custom log path: {$path}");
            } else {
                $this->error("✗ Cannot read path: {$path}");
                return 1;
            }
        }

        // Discover all log files
        $logFiles = $discovery->discoverLogFiles();

        // Add custom paths from cache
        foreach ($discovery->getCustomPaths() as $customPath) {
            if (is_readable($customPath) && !$logFiles->contains('path', $customPath)) {
                $logFiles->push([
                    'path' => $customPath,
                    'type' => 'custom',
                    'format' => 'nginx_combined',
                    'size' => filesize($customPath),
                    'readable' => true,
                ]);
            }
        }

        // Handle list option
        if ($this->option('list')) {
            $this->displayLogFiles($logFiles);
            return 0;
        }

        if ($logFiles->isEmpty()) {
            $this->warn('No log files discovered. Use --add-path to add custom paths.');
            $this->info('Common log locations checked:');
            $this->line('  - /var/log/nginx/access.log');
            $this->line('  - /var/log/apache2/access.log');
            $this->line('  - /var/log/httpd/access_log');
            return 1;
        }

        $this->startMonitoring($logFiles, $collector, (int) $this->option('interval'));

        return 0;
    }

    /**
     * Display discovered log files
     */
    private function displayLogFiles($logFiles): void
    {
        $this->info('Discovered Log Files:');
        $this->newLine();

        $headers = ['Path', 'Type', 'Format', 'Size', 'Readable'];
        $rows = $logFiles->map(fn($f) => [
            $f['path'],
            $f['type'],
            $f['format'] ?? 'unknown',
            $this->formatBytes($f['size'] ?? 0),
            $f['readable'] ? '✓' : '✗',
        ])->toArray();

        $this->table($headers, $rows);
    }

    /**
     * Start monitoring all discovered log files
     */
    private function startMonitoring($logFiles, LogCollectorService $collector, int $interval): void
    {
        $this->info('═══════════════════════════════════════════════════');
        $this->info('  Security One IDS - Auto Log Monitor');
        $this->info('═══════════════════════════════════════════════════');
        $this->newLine();
        
        $this->info("Monitoring {$logFiles->count()} log file(s):");
        foreach ($logFiles as $file) {
            $this->line("  • {$file['path']} ({$file['type']})");
            $this->filePositions[$file['path']] = filesize($file['path']);
        }
        $this->newLine();
        $this->info("Check interval: {$interval} seconds");
        $this->info('Press Ctrl+C to stop');
        $this->newLine();

        while (true) {
            $totalProcessed = 0;

            foreach ($logFiles as $file) {
                $processed = $this->processLogFile($file, $collector);
                $totalProcessed += $processed;
            }

            if ($totalProcessed > 0) {
                $this->info("[" . now()->format('H:i:s') . "] Dispatched {$totalProcessed} logs for processing");
            }

            sleep($interval);
        }
    }

    /**
     * Process a single log file for new entries
     */
    private function processLogFile(array $file, LogCollectorService $collector): int
    {
        $path = $file['path'];
        
        if (!file_exists($path) || !is_readable($path)) {
            return 0;
        }

        clearstatcache(true, $path);
        $currentSize = filesize($path);
        $lastPosition = $this->filePositions[$path] ?? 0;

        // File was rotated
        if ($currentSize < $lastPosition) {
            $this->warn("Log rotated: {$path}");
            $lastPosition = 0;
        }

        // No new data
        if ($currentSize === $lastPosition) {
            return 0;
        }

        // Read new lines
        $handle = fopen($path, 'r');
        fseek($handle, $lastPosition);

        $processed = 0;
        while (($line = fgets($handle)) !== false) {
            $logData = $collector->parseLogLine(trim($line));
            
            if ($logData) {
                // Add source info
                $logData['source'] = $file['type'];
                $logData['source_path'] = $path;
                
                ProcessAccessLog::dispatch($logData);
                $processed++;
            }
        }

        $this->filePositions[$path] = ftell($handle);
        fclose($handle);

        return $processed;
    }

    /**
     * Format bytes to human readable
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 2) . ' ' . $units[$i];
    }
}
