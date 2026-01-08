<?php

namespace App\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

/**
 * Log Collector Service
 * 
 * Collects and parses Nginx access logs for IDS/IPS analysis
 */
class LogCollectorService
{
    /**
     * Nginx log format pattern
     * Supports both combined format and extended format with X-Forwarded-For
     * Example: 192.168.1.1 - - [07/Jan/2026:10:00:00 +0000] "GET /api HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0" "-"
     */
    private const LOG_PATTERN = '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^\s]+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"/';

    /**
     * Collect logs from Nginx access log file
     *
     * @param string $logPath Path to nginx access log
     * @param int $lines Number of lines to read from end (default: 1000)
     * @return Collection
     */
    public function collectFromNginx(string $logPath, int $lines = 1000): Collection
    {
        if (!file_exists($logPath)) {
            Log::warning("Log file not found: {$logPath}");
            return collect([]);
        }

        // Read last N lines efficiently using tail
        $command = sprintf('tail -n %d %s', $lines, escapeshellarg($logPath));
        $output = shell_exec($command);

        if (!$output) {
            return collect([]);
        }

        $logLines = explode("\n", trim($output));
        
        return collect($logLines)
            ->filter(fn($line) => !empty($line))
            ->map(fn($line) => $this->parseLogLine($line))
            ->filter(); // Remove null values (failed parses)
    }

    /**
     * Parse a single Nginx log line
     *
     * @param string $line Raw log line
     * @return array|null Parsed data or null if parsing fails
     */
    public function parseLogLine(string $line): ?array
    {
        if (!preg_match(self::LOG_PATTERN, $line, $matches)) {
            Log::debug("Failed to parse log line: {$line}");
            return null;
        }

        [
            $full,
            $ip,
            $timestamp,
            $method,
            $uri,
            $protocol,
            $status,
            $size,
            $referer,
            $userAgent
        ] = $matches;

        return [
            'ip' => $ip,
            'timestamp' => $this->parseTimestamp($timestamp),
            'method' => $method,
            'uri' => $this->parseUri($uri),
            'protocol' => $protocol,
            'status' => (int) $status,
            'size' => (int) $size,
            'referer' => $referer === '-' ? null : $referer,
            'user_agent' => $userAgent,
            'raw_line' => $line,
        ];
    }

    /**
     * Parse timestamp from Nginx log format
     *
     * @param string $timestamp e.g., "07/Jan/2026:10:00:00 +0000"
     * @return string ISO 8601 format
     */
    private function parseTimestamp(string $timestamp): string
    {
        $dt = \DateTime::createFromFormat('d/M/Y:H:i:s O', $timestamp);
        return $dt ? $dt->format('Y-m-d H:i:s') : now()->toDateTimeString();
    }

    /**
     * Parse and sanitize URI
     *
     * @param string $uri Raw URI
     * @return array ['path' => string, 'query' => string|null]
     */
    private function parseUri(string $uri): array
    {
        $parts = parse_url($uri);
        
        return [
            'full' => $uri,
            'path' => $parts['path'] ?? '/',
            'query' => $parts['query'] ?? null,
        ];
    }

    /**
     * Collect logs within a time range
     *
     * @param string $logPath
     * @param \DateTimeInterface $start
     * @param \DateTimeInterface $end
     * @return Collection
     */
    public function collectTimeRange(string $logPath, \DateTimeInterface $start, \DateTimeInterface $end): Collection
    {
        // For simplicity, collect recent logs and filter
        // In production, consider using log rotation files
        return $this->collectFromNginx($logPath, 10000)
            ->filter(function ($log) use ($start, $end) {
                $logTime = new \DateTime($log['timestamp']);
                return $logTime >= $start && $logTime <= $end;
            });
    }

    /**
     * Get log file path from configuration
     *
     * @return string
     */
    public static function getDefaultLogPath(): string
    {
        return config('ids.nginx_log_path', '/var/log/nginx/access.log');
    }
}
