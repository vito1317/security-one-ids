<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

/**
 * Desktop Log Collector Service
 * 
 * Collects system logs from personal computers (Linux, macOS, Windows)
 * for IDS/IPS analysis including authentication, system events, and network connections.
 */
class DesktopLogCollector
{
    private string $platform;
    private array $logPaths = [];
    
    public function __construct()
    {
        $this->platform = $this->detectPlatform();
        $this->logPaths = $this->getLogPaths();
    }
    
    /**
     * Detect the current operating system
     */
    private function detectPlatform(): string
    {
        if (stripos(PHP_OS, 'WIN') === 0) {
            return 'windows';
        } elseif (stripos(PHP_OS, 'Darwin') !== false) {
            return 'macos';
        }
        return 'linux';
    }
    
    /**
     * Get log file paths based on platform
     */
    private function getLogPaths(): array
    {
        return match ($this->platform) {
            'linux' => [
                'auth' => [
                    '/var/log/auth.log',           // Debian/Ubuntu
                    '/var/log/secure',             // RHEL/CentOS
                ],
                'syslog' => [
                    '/var/log/syslog',
                    '/var/log/messages',
                ],
                'firewall' => [
                    '/var/log/ufw.log',
                    '/var/log/iptables.log',
                ],
            ],
            'macos' => [
                'auth' => [
                    '/var/log/system.log',
                ],
                'syslog' => [
                    '/var/log/system.log',
                ],
                'firewall' => [
                    '/var/log/appfirewall.log',
                ],
            ],
            'windows' => [
                // Windows uses Event Log API, not files
                'auth' => ['Security'],
                'syslog' => ['System'],
                'firewall' => ['Windows Firewall With Advanced Security'],
            ],
            default => [],
        };
    }
    
    /**
     * Get current platform
     */
    public function getPlatform(): string
    {
        return $this->platform;
    }
    
    /**
     * Collect authentication logs (SSH, sudo, login attempts)
     */
    public function collectAuthLogs(int $lines = 100): array
    {
        $logs = [];
        
        foreach ($this->logPaths['auth'] ?? [] as $path) {
            if ($this->platform === 'windows') {
                $logs = array_merge($logs, $this->collectWindowsEventLog($path, $lines));
            } elseif (file_exists($path) && is_readable($path)) {
                $logs = array_merge($logs, $this->tailFile($path, $lines));
            }
        }
        
        return $this->parseAuthLogs($logs);
    }
    
    /**
     * Collect system logs
     */
    public function collectSysLogs(int $lines = 100): array
    {
        $logs = [];
        
        foreach ($this->logPaths['syslog'] ?? [] as $path) {
            if ($this->platform === 'windows') {
                $logs = array_merge($logs, $this->collectWindowsEventLog($path, $lines));
            } elseif (file_exists($path) && is_readable($path)) {
                $logs = array_merge($logs, $this->tailFile($path, $lines));
            }
        }
        
        return $logs;
    }
    
    /**
     * Get active network connections
     */
    public function collectNetworkConnections(): array
    {
        $connections = [];
        
        try {
            $output = match ($this->platform) {
                'linux', 'macos' => shell_exec('netstat -tunap 2>/dev/null || ss -tunap 2>/dev/null'),
                'windows' => shell_exec('netstat -ano'),
                default => '',
            };
            
            if ($output) {
                $connections = $this->parseNetstatOutput($output);
            }
        } catch (\Exception $e) {
            Log::warning('Failed to collect network connections: ' . $e->getMessage());
        }
        
        return $connections;
    }
    
    /**
     * Get failed login attempts
     */
    public function getFailedLogins(int $hours = 24): array
    {
        $authLogs = $this->collectAuthLogs(500);
        $failedAttempts = [];
        $cutoffTime = time() - ($hours * 3600);
        
        foreach ($authLogs as $log) {
            if (isset($log['type']) && $log['type'] === 'failed_login') {
                if (isset($log['timestamp']) && strtotime($log['timestamp']) > $cutoffTime) {
                    $failedAttempts[] = $log;
                }
            }
        }
        
        return $failedAttempts;
    }
    
    /**
     * Get successful logins
     */
    public function getSuccessfulLogins(int $hours = 24): array
    {
        $authLogs = $this->collectAuthLogs(500);
        $successfulLogins = [];
        $cutoffTime = time() - ($hours * 3600);
        
        foreach ($authLogs as $log) {
            if (isset($log['type']) && $log['type'] === 'successful_login') {
                if (isset($log['timestamp']) && strtotime($log['timestamp']) > $cutoffTime) {
                    $successfulLogins[] = $log;
                }
            }
        }
        
        return $successfulLogins;
    }
    
    /**
     * Tail a file to get last N lines
     */
    private function tailFile(string $path, int $lines): array
    {
        $result = [];
        
        try {
            $output = shell_exec("tail -n {$lines} " . escapeshellarg($path) . " 2>/dev/null");
            if ($output) {
                $result = array_filter(explode("\n", $output));
            }
        } catch (\Exception $e) {
            Log::warning("Failed to tail file {$path}: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Parse authentication log lines
     */
    private function parseAuthLogs(array $lines): array
    {
        $parsed = [];
        
        foreach ($lines as $line) {
            if (empty($line)) continue;
            
            $entry = [
                'raw' => $line,
                'timestamp' => null,
                'type' => 'unknown',
                'user' => null,
                'ip' => null,
                'service' => null,
            ];
            
            // Extract timestamp (common syslog format)
            if (preg_match('/^(\w+\s+\d+\s+\d+:\d+:\d+)/', $line, $matches)) {
                $entry['timestamp'] = $matches[1] . ' ' . date('Y');
            }
            
            // Detect failed SSH login
            if (preg_match('/Failed password for(?: invalid user)? (\S+) from (\S+)/', $line, $matches)) {
                $entry['type'] = 'failed_login';
                $entry['user'] = $matches[1];
                $entry['ip'] = $matches[2];
                $entry['service'] = 'ssh';
            }
            // Detect successful SSH login
            elseif (preg_match('/Accepted (?:password|publickey) for (\S+) from (\S+)/', $line, $matches)) {
                $entry['type'] = 'successful_login';
                $entry['user'] = $matches[1];
                $entry['ip'] = $matches[2];
                $entry['service'] = 'ssh';
            }
            // Detect sudo attempts
            elseif (preg_match('/sudo:\s+(\S+).*COMMAND=(.*)/', $line, $matches)) {
                $entry['type'] = 'sudo_command';
                $entry['user'] = $matches[1];
                $entry['command'] = $matches[2];
                $entry['service'] = 'sudo';
            }
            // Detect authentication failure
            elseif (preg_match('/authentication failure.*user=(\S+)/', $line, $matches)) {
                $entry['type'] = 'auth_failure';
                $entry['user'] = $matches[1];
            }
            
            if ($entry['type'] !== 'unknown') {
                $parsed[] = $entry;
            }
        }
        
        return $parsed;
    }
    
    /**
     * Parse netstat output
     */
    private function parseNetstatOutput(string $output): array
    {
        $connections = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            // Skip headers and empty lines
            if (empty($line) || preg_match('/^(Proto|Active|tcp|udp)\s/i', $line) === false) {
                continue;
            }
            
            // Parse TCP/UDP connections
            if (preg_match('/^(tcp|udp)\d?\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)?/i', $line, $matches)) {
                $connections[] = [
                    'protocol' => strtolower($matches[1]),
                    'local' => $matches[2],
                    'remote' => $matches[3],
                    'state' => $matches[4] ?? 'UNKNOWN',
                ];
            }
        }
        
        return $connections;
    }
    
    /**
     * Collect Windows Event Log entries using PowerShell
     */
    private function collectWindowsEventLog(string $logName, int $count): array
    {
        $logs = [];
        
        try {
            // PowerShell command to get security events
            $psCommand = match ($logName) {
                'Security' => "Get-WinEvent -LogName Security -MaxEvents {$count} | Select-Object TimeCreated,Id,Message | ConvertTo-Json",
                'System' => "Get-WinEvent -LogName System -MaxEvents {$count} | Select-Object TimeCreated,Id,Message | ConvertTo-Json",
                default => "Get-WinEvent -LogName '{$logName}' -MaxEvents {$count} | Select-Object TimeCreated,Id,Message | ConvertTo-Json",
            };
            
            $output = shell_exec("powershell -Command \"{$psCommand}\" 2>/dev/null");
            
            if ($output) {
                $events = json_decode($output, true);
                if (is_array($events)) {
                    // Handle single event (not array)
                    if (isset($events['TimeCreated'])) {
                        $events = [$events];
                    }
                    
                    foreach ($events as $event) {
                        $logs[] = $this->parseWindowsEvent($event);
                    }
                }
            }
        } catch (\Exception $e) {
            Log::warning("Failed to collect Windows Event Log: " . $e->getMessage());
        }
        
        return $logs;
    }
    
    /**
     * Parse Windows Event into standard format
     */
    private function parseWindowsEvent(array $event): array
    {
        $entry = [
            'raw' => $event['Message'] ?? '',
            'timestamp' => $event['TimeCreated'] ?? null,
            'type' => 'unknown',
            'event_id' => $event['Id'] ?? null,
            'user' => null,
            'ip' => null,
            'service' => 'windows',
        ];
        
        $eventId = $event['Id'] ?? 0;
        $message = $event['Message'] ?? '';
        
        // Windows Security Event IDs
        // 4624 - Successful login
        // 4625 - Failed login
        // 4634 - Logoff
        // 4648 - Explicit credential logon
        // 4672 - Special privileges assigned
        // 4720 - User account created
        // 4726 - User account deleted
        
        switch ($eventId) {
            case 4625:
                $entry['type'] = 'failed_login';
                if (preg_match('/Account Name:\s+(\S+)/i', $message, $m)) {
                    $entry['user'] = $m[1];
                }
                if (preg_match('/Source Network Address:\s+(\S+)/i', $message, $m)) {
                    $entry['ip'] = $m[1];
                }
                break;
                
            case 4624:
                $entry['type'] = 'successful_login';
                if (preg_match('/Account Name:\s+(\S+)/i', $message, $m)) {
                    $entry['user'] = $m[1];
                }
                if (preg_match('/Source Network Address:\s+(\S+)/i', $message, $m)) {
                    $entry['ip'] = $m[1];
                }
                break;
                
            case 4672:
                $entry['type'] = 'privilege_escalation';
                if (preg_match('/Account Name:\s+(\S+)/i', $message, $m)) {
                    $entry['user'] = $m[1];
                }
                break;
                
            case 4720:
                $entry['type'] = 'user_created';
                if (preg_match('/New Account:\s+Account Name:\s+(\S+)/i', $message, $m)) {
                    $entry['user'] = $m[1];
                }
                break;
        }
        
        return $entry;
    }
    
    /**
     * Collect macOS unified logs using log command
     */
    public function collectMacOsLogs(int $minutes = 60): array
    {
        $logs = [];
        
        if ($this->platform !== 'macos') {
            return $logs;
        }
        
        try {
            // Query authentication events from unified log
            $output = shell_exec("log show --predicate 'subsystem == \"com.apple.securityd\" OR category == \"authentication\"' --last {$minutes}m --style json 2>/dev/null");
            
            if ($output) {
                $events = json_decode($output, true);
                if (is_array($events)) {
                    foreach ($events as $event) {
                        $logs[] = $this->parseMacOsEvent($event);
                    }
                }
            }
            
            // Also check auth.log if available
            if (file_exists('/var/log/authd.log')) {
                $authLogs = $this->tailFile('/var/log/authd.log', 100);
                $logs = array_merge($logs, $this->parseAuthLogs($authLogs));
            }
            
        } catch (\Exception $e) {
            Log::warning("Failed to collect macOS logs: " . $e->getMessage());
        }
        
        return $logs;
    }
    
    /**
     * Parse macOS unified log event
     */
    private function parseMacOsEvent(array $event): array
    {
        $entry = [
            'raw' => $event['eventMessage'] ?? '',
            'timestamp' => $event['timestamp'] ?? null,
            'type' => 'unknown',
            'user' => null,
            'ip' => null,
            'service' => 'macos',
            'process' => $event['processImagePath'] ?? null,
        ];
        
        $message = $event['eventMessage'] ?? '';
        
        // Detect authentication events
        if (preg_match('/authentication (succeeded|failed)/i', $message, $m)) {
            $entry['type'] = $m[1] === 'succeeded' ? 'successful_login' : 'failed_login';
        }
        // Detect sudo
        if (preg_match('/sudo.*user=(\S+)/i', $message, $m)) {
            $entry['type'] = 'sudo_command';
            $entry['user'] = $m[1];
        }
        // Detect SSH
        if (preg_match('/sshd.*from (\S+)/i', $message, $m)) {
            $entry['ip'] = $m[1];
            $entry['service'] = 'ssh';
        }
        
        return $entry;
    }
    
    /**
     * Get all authentication logs (cross-platform)
     */
    public function getAllAuthLogs(int $lines = 200): array
    {
        return match ($this->platform) {
            'windows' => $this->collectWindowsEventLog('Security', $lines),
            'macos' => $this->collectMacOsLogs(60),
            default => $this->collectAuthLogs($lines),
        };
    }
    
    /**
     * Get summary of system security status
     */
    public function getSecuritySummary(): array
    {
        $failedLogins = $this->getFailedLogins(24);
        $successfulLogins = $this->getSuccessfulLogins(24);
        $connections = $this->collectNetworkConnections();
        
        // Count external connections
        $externalConnections = array_filter($connections, function ($conn) {
            $remote = $conn['remote'] ?? '';
            return !str_starts_with($remote, '127.') && 
                   !str_starts_with($remote, '192.168.') &&
                   !str_starts_with($remote, '10.') &&
                   !str_starts_with($remote, '::1');
        });
        
        return [
            'platform' => $this->platform,
            'failed_logins_24h' => count($failedLogins),
            'successful_logins_24h' => count($successfulLogins),
            'total_connections' => count($connections),
            'external_connections' => count($externalConnections),
            'top_failed_ips' => $this->getTopFailedIps($failedLogins),
            'timestamp' => now()->toIso8601String(),
        ];
    }
    
    /**
     * Get top IPs with failed logins
     */
    private function getTopFailedIps(array $failedLogins): array
    {
        $ipCounts = [];
        
        foreach ($failedLogins as $attempt) {
            $ip = $attempt['ip'] ?? 'unknown';
            $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
        }
        
        arsort($ipCounts);
        return array_slice($ipCounts, 0, 5, true);
    }
}
