<?php

namespace App\Console\Commands;

use App\Services\LogCollectorService;
use App\Services\TrafficAnalyzer;
use Illuminate\Console\Command;

/**
 * Generate Traffic Report Command
 * 
 * Analyze recent traffic and generate comprehensive statistics report
 */
class GenerateTrafficReport extends Command
{
    protected $signature = 'ids:traffic-report 
                            {--lines=1000 : Number of recent log lines to analyze}
                            {--format=json : Output format (json, table)}
                            {--save : Save report to file}';

    protected $description = 'Generate traffic analysis report from Nginx logs';

    public function handle(LogCollectorService $collector, TrafficAnalyzer $analyzer): int
    {
        $this->info('Generating traffic report...');

        $lines = (int) $this->option('lines');
        $format = $this->option('format');
        
        // Collect recent logs
        $logPath = LogCollectorService::getDefaultLogPath();
        $logs = $collector->collectFromNginx($logPath, $lines);

        if ($logs->isEmpty()) {
            $this->warn('No logs found to analyze');
            return 1;
        }

        $this->info("Analyzing {$logs->count()} log entries...");

        // Generate statistics
        $stats = $analyzer->generateStats($logs);

        // Display report
        if ($format === 'table') {
            $this->displayTableReport($stats);
        } else {
            $this->displayJsonReport($stats);
        }

        // Save to file if requested
        if ($this->option('save')) {
            $this->saveReport($stats);
        }

        return 0;
    }

    private function displayTableReport(array $stats): void
    {
        $this->newLine();
        $this->info('=== TRAFFIC SUMMARY ===');
        $this->table(
            ['Metric', 'Value'],
            [
                ['Total Requests', number_format($stats['summary']['total_requests'])],
                ['Unique IPs', number_format($stats['summary']['unique_ips'])],
                ['Unique URLs', number_format($stats['summary']['unique_urls'])],
                ['QPS (1 min)', $stats['qps']['1min']],
                ['QPS (5 min)', $stats['qps']['5min']],
            ]
        );

        $this->newLine();
        $this->info('=== TOP IPs ===');
        $topIps = [];
        foreach (array_slice($stats['ip_analysis']['top_ips'], 0, 10, true) as $ip => $count) {
            $topIps[] = [$ip, $count];
        }
        $this->table(['IP Address', 'Requests'], $topIps);

        $this->newLine();
        $this->info('=== HTTP STATUS CODES ===');
        $statusCodes = [];
        foreach ($stats['status_codes'] as $code => $count) {
            $statusCodes[] = [$code, $count];
        }
        $this->table(['Status Code', 'Count'], $statusCodes);

        if (!empty($stats['ip_analysis']['suspicious_ips'])) {
            $this->newLine();
            $this->warn('=== SUSPICIOUS IPs (High Request Rate) ===');
            $suspIps = [];
            foreach ($stats['ip_analysis']['suspicious_ips'] as $ip => $count) {
                $suspIps[] = [$ip, $count];
            }
            $this->table(['IP Address', 'Requests'], $suspIps);
        }

        if (!empty($stats['user_agent_analysis']['suspicious_agents'])) {
            $this->newLine();
            $this->warn('=== SUSPICIOUS USER AGENTS ===');
            $suspAgents = [];
            foreach (array_slice($stats['user_agent_analysis']['suspicious_agents'], 0, 10, true) as $ua => $count) {
                $suspAgents[] = [substr($ua, 0, 60), $count];
            }
            $this->table(['User Agent', 'Requests'], $suspAgents);
        }
    }

    private function displayJsonReport(array $stats): void
    {
        $this->line(json_encode($stats, JSON_PRETTY_PRINT));
    }

    private function saveReport(array $stats): void
    {
        $filename = storage_path('logs/traffic-report-' . now()->format('Y-m-d-His') . '.json');
        file_put_contents($filename, json_encode($stats, JSON_PRETTY_PRINT));
        $this->info("Report saved to: {$filename}");
    }
}
