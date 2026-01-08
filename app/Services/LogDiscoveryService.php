<?php

namespace App\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

/**
 * Log Discovery Service
 * 
 * Auto-discovers web server log files on the system
 */
class LogDiscoveryService
{
    /**
     * Common log file locations to scan
     */
    private const LOG_PATHS = [
        // Container's own Nginx
        '/var/log/nginx/access.log',
        '/var/log/nginx/*/access.log',
        
        // Host-mounted logs (via docker-compose volumes)
        '/var/log/host-nginx/access.log',
        '/var/log/host-nginx/*/access.log',
        '/var/log/host-nginx/*-access.log',
        '/var/log/host-apache2/access.log',
        '/var/log/host-apache2/*/access.log',
        '/var/log/host-apache2/*-access.log',
        '/var/log/host-apache2/other_vhosts_access.log',
        '/var/log/host-httpd/access_log',
        '/var/log/host-httpd/*/access_log',
        
        // Standard Nginx paths
        '/usr/local/nginx/logs/access.log',
        
        // Standard Apache paths  
        '/var/log/apache2/access.log',
        '/var/log/httpd/access_log',
        
        // Custom paths
        '/var/www/*/logs/access.log',
        '/home/*/logs/access.log',
    ];

    /**
     * Log format patterns for different servers
     */
    private const LOG_FORMATS = [
        'nginx_combined' => '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^\s]+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"/',
        'apache_combined' => '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^\s]+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"/',
        'apache_common' => '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^\s]+) ([^"]+)" (\d+) (\d+)/',
    ];

    /**
     * Discover all accessible log files
     */
    public function discoverLogFiles(): Collection
    {
        $discovered = collect();

        foreach (self::LOG_PATHS as $pattern) {
            $files = glob($pattern);
            if ($files) {
                foreach ($files as $file) {
                    if (is_readable($file) && is_file($file)) {
                        $info = $this->getLogInfo($file);
                        if ($info) {
                            $discovered->push($info);
                        }
                    }
                }
            }
        }

        // Also check custom paths from config
        $customPaths = config('ids.custom_log_paths', []);
        foreach ($customPaths as $path) {
            if (is_readable($path) && is_file($path)) {
                $info = $this->getLogInfo($path);
                if ($info) {
                    $discovered->push($info);
                }
            }
        }

        return $discovered->unique('path');
    }

    /**
     * Get information about a log file
     */
    private function getLogInfo(string $path): ?array
    {
        $format = $this->detectFormat($path);
        if (!$format) {
            return null;
        }

        $type = $this->detectServerType($path);
        
        return [
            'path' => $path,
            'type' => $type,
            'format' => $format,
            'size' => filesize($path),
            'modified' => filemtime($path),
            'readable' => is_readable($path),
        ];
    }

    /**
     * Detect the log format by reading sample lines
     */
    private function detectFormat(string $path): ?string
    {
        $handle = @fopen($path, 'r');
        if (!$handle) {
            return null;
        }

        // Read a few sample lines from the end
        $lines = [];
        fseek($handle, max(0, filesize($path) - 4096));
        while (($line = fgets($handle)) !== false) {
            if (trim($line)) {
                $lines[] = trim($line);
            }
        }
        fclose($handle);

        if (empty($lines)) {
            return null;
        }

        // Try to match against known formats
        $sampleLine = end($lines);
        
        foreach (self::LOG_FORMATS as $name => $pattern) {
            if (preg_match($pattern, $sampleLine)) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Detect server type from path
     */
    private function detectServerType(string $path): string
    {
        if (str_contains($path, 'nginx')) {
            return 'nginx';
        }
        if (str_contains($path, 'apache') || str_contains($path, 'httpd')) {
            return 'apache';
        }
        return 'unknown';
    }

    /**
     * Add a custom log path to monitor
     */
    public function addCustomPath(string $path): bool
    {
        if (!is_readable($path)) {
            return false;
        }

        $customPaths = config('ids.custom_log_paths', []);
        if (!in_array($path, $customPaths)) {
            $customPaths[] = $path;
            // Store in cache for persistence
            cache()->forever('ids_custom_log_paths', $customPaths);
        }

        return true;
    }

    /**
     * Get custom paths from cache
     */
    public function getCustomPaths(): array
    {
        return cache()->get('ids_custom_log_paths', []);
    }

    /**
     * Get pattern for a specific format
     */
    public static function getPattern(string $format): ?string
    {
        return self::LOG_FORMATS[$format] ?? self::LOG_FORMATS['nginx_combined'];
    }
}
