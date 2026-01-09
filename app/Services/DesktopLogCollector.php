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
        
        // macOS uses unified logging - use the log command
        if ($this->platform === 'macos') {
            Log::debug('Collecting macOS logs via unified logging');
            return $this->collectMacOsLogs(60);
        }
        
        foreach ($this->logPaths['auth'] ?? [] as $path) {
            if ($this->platform === 'windows') {
                Log::debug("Collecting Windows Event Log: {$path}");
                $windowsLogs = $this->collectWindowsEventLog($path, $lines);
                Log::debug("Windows Event Log returned " . count($windowsLogs) . " entries");
                $logs = array_merge($logs, $windowsLogs);
            } elseif (file_exists($path) && is_readable($path)) {
                Log::debug("Reading log file: {$path}");
                $logs = array_merge($logs, $this->tailFile($path, $lines));
            } else {
                Log::debug("Log file not accessible: {$path}");
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
            // Ensure $line is a string (Windows Event Log may return arrays)
            if (is_array($line)) {
                $line = json_encode($line);
            }
            if (empty($line) || !is_string($line)) continue;
            
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
            // Use simpler PowerShell command - write to temp file then read
            // Security Event Log IDs for login events:
            // 4624 = Successful logon
            // 4625 = Failed logon
            // 4634 = Logoff
            // 4648 = Explicit credentials logon
            
            if ($logName === 'Security') {
                // Filter for login events only
                $psCommand = 'powershell -NoProfile -Command "Get-WinEvent -LogName Security -MaxEvents ' . $count . ' -FilterXPath \'*[System[(EventID=4624 or EventID=4625 or EventID=4634)]]\' -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,@{n=\'Message\';e={$_.Message.Substring(0,[Math]::Min(500,$_.Message.Length))}} | ConvertTo-Json"';
            } else {
                $psCommand = 'powershell -NoProfile -Command "Get-WinEvent -LogName ' . $logName . ' -MaxEvents ' . $count . ' -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,@{n=\'Message\';e={$_.Message.Substring(0,[Math]::Min(500,$_.Message.Length))}} | ConvertTo-Json"';
            }
            
            Log::debug("Executing: {$psCommand}");
            
            $output = shell_exec($psCommand . ' 2>&1');
            
            Log::debug("PowerShell output length: " . strlen($output ?? ''));
            Log::debug("PowerShell output preview: " . substr($output ?? '', 0, 200));
            
            if ($output && strlen($output) > 2) {
                $events = json_decode($output, true);
                
                if (json_last_error() !== JSON_ERROR_NONE) {
                    Log::debug("JSON decode error: " . json_last_error_msg());
                    Log::debug("Raw output: " . substr($output, 0, 500));
                    return $logs;
                }
                
                if (is_array($events)) {
                    // Handle single event (PowerShell returns object not array for single result)
                    if (isset($events['TimeCreated'])) {
                        $events = [$events];
                    }
                    
                    Log::debug("Windows Event Log parsed " . count($events) . " events");
                    
                    foreach ($events as $event) {
                        $logs[] = $this->parseWindowsEvent($event);
                    }
                }
            } else {
                Log::debug("No output from PowerShell command");
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
            // macOS authentication/authorization events use specific subsystems
            // Try to find actual login events with targeted predicates
            $predicates = [
                // opendirectoryd handles user authentication
                'subsystem == "com.apple.opendirectoryd"',
                // Authorization and security events  
                'subsystem == "com.apple.authd" OR subsystem == "com.apple.Authorization"',
                // Login/authentication process events with specific messages
                'eventMessage CONTAINS "authentication" OR eventMessage CONTAINS "password" OR eventMessage CONTAINS "login"',
                // su and sudo processes (may need root to see these)
                'process == "su" OR process == "sudo"',
            ];
            
            foreach ($predicates as $predicate) {
                $output = shell_exec("log show --predicate '{$predicate}' --last {$minutes}m --style json 2>/dev/null");
                
                if ($output && strlen($output) > 10) {
                    $events = json_decode($output, true);
                    if (is_array($events) && !empty($events)) {
                        Log::debug("macOS unified log matched " . count($events) . " events with predicate: {$predicate}");
                        foreach ($events as $event) {
                            $parsed = $this->parseMacOsEvent($event);
                            // Only add if it's a recognized authentication event
                            if ($parsed['type'] !== 'unknown') {
                                $logs[] = $parsed;
                            }
                        }
                        if (!empty($logs)) {
                            break; // Found useful events, stop trying more predicates
                        }
                    }
                }
            }
            
            // Always try to read /var/log/system.log for su/sudo events (may not be in unified log)
            Log::debug("Checking /var/log/system.log for su/sudo events");
            $output = shell_exec("sudo grep -iE '(su:|sudo:|authentication|password|login failure)' /var/log/system.log 2>/dev/null | tail -200");
            if ($output) {
                $lines = array_filter(explode("\n", $output));
                Log::debug("Found " . count($lines) . " lines in system.log");
                foreach ($lines as $line) {
                    $parsed = $this->parseMacOsLogLine($line);
                    if ($parsed['type'] !== 'unknown') {
                        $logs[] = $parsed;
                    }
                }
            }
            
            // Try ASL (Apple System Log) for older macOS
            if (empty($logs) && file_exists('/var/log/asl/')) {
                $output = shell_exec("syslog -k Facility auth -k Level le Warning 2>/dev/null | tail -100");
                if ($output) {
                    $lines = array_filter(explode("\n", $output));
                    foreach ($lines as $line) {
                        $logs[] = $this->parseMacOsLogLine($line);
                    }
                }
            }
            
        } catch (\Exception $e) {
            Log::warning("Failed to collect macOS logs: " . $e->getMessage());
        }
        
        Log::debug("Total macOS authentication logs collected: " . count($logs));
        return $logs;
    }
    
    /**
     * Parse a macOS system log line (text format)
     */
    private function parseMacOsLogLine(string $line): array
    {
        $entry = [
            'raw' => $line,
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => 'unknown',
            'user' => null,
            'ip' => null,
            'service' => 'macos',
        ];
        
        // Extract timestamp if present (macOS syslog format: "Jan  9 12:34:56")
        if (preg_match('/^(\w+\s+\d+\s+\d+:\d+:\d+)/', $line, $m)) {
            $entry['timestamp'] = $m[1] . ' ' . date('Y');
        }
        
        // su failures
        if (preg_match('/su:\s*(BAD SU|FAILED SU|authentication failure)/i', $line)) {
            $entry['type'] = 'failed_login';
            $entry['service'] = 'su';
        }
        // su success
        elseif (preg_match('/su:\s*\S+\s+to\s+(\S+)/i', $line, $m)) {
            $entry['type'] = 'successful_login';
            $entry['user'] = $m[1];
            $entry['service'] = 'su';
        }
        // sudo failures
        elseif (preg_match('/sudo:\s*(\S+).*incorrect password/i', $line, $m)) {
            $entry['type'] = 'failed_login';
            $entry['user'] = $m[1];
            $entry['service'] = 'sudo';
        }
        // Authentication succeeded/failed patterns
        elseif (preg_match('/authentication\s+(succeeded|success|failed|failure)/i', $line, $m)) {
            $entry['type'] = (strtolower($m[1]) === 'succeeded' || strtolower($m[1]) === 'success') 
                ? 'successful_login' : 'failed_login';
        }
        // Login window patterns
        elseif (preg_match('/(login|password)\s+(accepted|rejected|failed|incorrect)/i', $line, $m)) {
            $entry['type'] = (strtolower($m[2]) === 'accepted') ? 'successful_login' : 'failed_login';
        }
        
        // Extract username
        if (preg_match('/user[=:\s]+["\']?(\S+?)["\']?[\s,\]$]/i', $line, $m)) {
            $entry['user'] = trim($m[1], '"\'');
        }
        return $entry;
    }    
    /**
     * Parse macOS unified log event
     */
    private function parseMacOsEvent(array $event): array
    {
        $message = $event['eventMessage'] ?? $event['message'] ?? '';
        
        $entry = [
            'raw' => $message,
            'timestamp' => $event['timestamp'] ?? $event['timeCreate'] ?? date('Y-m-d H:i:s'),
            'type' => 'unknown',
            'user' => null,
            'ip' => null,
            'service' => 'macos',
            'process' => $event['processImagePath'] ?? $event['process'] ?? null,
        ];
        
        // Detect authentication success/failure patterns (case-insensitive)
        if (preg_match('/authentication\s+(succeeded|failed|failure)/i', $message, $m)) {
            $entry['type'] = ($m[1] === 'succeeded') ? 'successful_login' : 'failed_login';
        }
        // Password checking patterns  
        elseif (preg_match('/password\s+(accepted|failed|incorrect|invalid)/i', $message, $m)) {
            $entry['type'] = ($m[1] === 'accepted') ? 'successful_login' : 'failed_login';
        }
        // Login window events
        elseif (preg_match('/(login|logon)\s+(successful|succeeded|failed|failure)/i', $message, $m)) {
            $entry['type'] = ($m[2] === 'successful' || $m[2] === 'succeeded') ? 'successful_login' : 'failed_login';
        }
        // User session events
        elseif (preg_match('/user\s+(\S+)\s+(logged in|logged out|authentication failed)/i', $message, $m)) {
            $entry['user'] = $m[1];
            $entry['type'] = str_contains($m[2], 'failed') ? 'failed_login' : 
                            (str_contains($m[2], 'logged in') ? 'successful_login' : 'logout');
        }
        // Security authorization events
        elseif (preg_match('/Authorization\s+(success|denied|allowed)/i', $message, $m)) {
            $entry['type'] = ($m[1] === 'success' || $m[1] === 'allowed') ? 'successful_login' : 'failed_login';
        }
        
        // Detect sudo commands
        if (preg_match('/sudo.*user[=:]\s*(\S+)/i', $message, $m)) {
            $entry['type'] = 'sudo_command';
            $entry['user'] = $m[1];
        }
        
        // Detect SSH connections (extract IP)
        if (preg_match('/sshd.*from\s+(\d+\.\d+\.\d+\.\d+)/i', $message, $m)) {
            $entry['ip'] = $m[1];
            $entry['service'] = 'ssh';
        }
        
        // Extract username if present
        if (!$entry['user'] && preg_match('/user[=:\s]+["\']?(\S+?)["\']?[\s,\]]/i', $message, $m)) {
            $entry['user'] = trim($m[1], '"\'');
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
