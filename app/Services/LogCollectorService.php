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
     * Supports extended WAF format with X-Forwarded-For
     * Format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"
     * Example: 172.22.0.2 - - [07/Jan/2026:10:00:00 +0000] "GET /api HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0" "203.0.113.50, 10.0.0.1"
     */
    private const LOG_PATTERN = '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^\s]+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"(?:\s+"([^"]*)")?/';

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
            $remoteAddr,
            $timestamp,
            $method,
            $uri,
            $protocol,
            $status,
            $size,
            $referer,
            $userAgent
        ] = $matches;

        // Extract X-Forwarded-For if present (10th capture group)
        $xForwardedFor = $matches[10] ?? null;
        
        // Determine real client IP:
        // 1. If X-Forwarded-For exists and is not "-", use the first IP in the chain (original client)
        // 2. Otherwise, fall back to remote_addr
        $realIp = $remoteAddr;
        if ($xForwardedFor && $xForwardedFor !== '-' && !empty(trim($xForwardedFor))) {
            // X-Forwarded-For format: "client, proxy1, proxy2"
            // The first IP is the original client
            $forwardedIps = array_map('trim', explode(',', $xForwardedFor));
            if (!empty($forwardedIps[0]) && filter_var($forwardedIps[0], FILTER_VALIDATE_IP)) {
                $realIp = $forwardedIps[0];
                Log::debug("Using X-Forwarded-For IP", [
                    'original' => $remoteAddr,
                    'x_forwarded_for' => $xForwardedFor,
                    'real_ip' => $realIp
                ]);
            }
        }

        return [
            'ip' => $realIp,
            'remote_addr' => $remoteAddr, // Keep original for debugging
            'x_forwarded_for' => $xForwardedFor,
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
