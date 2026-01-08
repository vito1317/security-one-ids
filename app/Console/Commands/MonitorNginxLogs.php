<?php

namespace App\Console\Commands;

use App\Jobs\ProcessAccessLog;
use App\Services\LogCollectorService;
use Illuminate\Console\Command;

/**
 * Monitor Nginx Logs Command
 * 
 * Continuously monitor Nginx access logs and dispatch processing jobs
 */
class MonitorNginxLogs extends Command
{
    protected $signature = 'ids:monitor-logs 
                            {--path= : Custom log file path}
                            {--lines=100 : Number of lines to process per batch}
                            {--interval=5 : Seconds between checks}';

    protected $description = 'Monitor Nginx access logs and process them through IDS';

    private int $lastPosition = 0;

    public function handle(LogCollectorService $collector): int
    {
        $logPath = $this->option('path') ?? LogCollectorService::getDefaultLogPath();
        $lines = (int) $this->option('lines');
        $interval = (int) $this->option('interval');

        $this->info("Starting log monitoring...");
        $this->info("Log path: {$logPath}");
        $this->info("Batch size: {$lines} lines");
        $this->info("Check interval: {$interval} seconds");

        // Initialize last position
        if (file_exists($logPath)) {
            $this->lastPosition = filesize($logPath);
        }

        while (true) {
            try {
                $this->processNewLogs($collector, $logPath, $lines);
                sleep($interval);
            } catch (\Exception $e) {
                $this->error("Error processing logs: " . $e->getMessage());
                sleep($interval);
            }
        }

        return 0;
    }

    private function processNewLogs(LogCollectorService $collector, string $logPath, int $maxLines): void
    {
        if (!file_exists($logPath)) {
            return;
        }

        // Clear stat cache to get fresh file size
        clearstatcache(true, $logPath);
        $currentSize = filesize($logPath);
        
        // File was rotated
        if ($currentSize < $this->lastPosition) {
            $this->warn('Log file rotated, resetting position');
            $this->lastPosition = 0;
        }

        // No new data
        if ($currentSize === $this->lastPosition) {
            return;
        }

        // Read new lines
        $handle = fopen($logPath, 'r');
        fseek($handle, $this->lastPosition);
        
        $processedLines = 0;
        while (($line = fgets($handle)) !== false && $processedLines < $maxLines) {
            $logData = $collector->parseLogLine(trim($line));
            
            if ($logData) {
                ProcessAccessLog::dispatch($logData);
                $processedLines++;
            }
        }

        $this->lastPosition = ftell($handle);
        fclose($handle);

        if ($processedLines > 0) {
            $this->info("Dispatched {$processedLines} logs for processing");
        }
    }
}
