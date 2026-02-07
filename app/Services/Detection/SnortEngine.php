<?php

namespace App\Services\Detection;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * Snort 3 IPS Detection Engine
 *
 * Manages Snort 3 process lifecycle, parses alerts, and provides status information.
 * Supports IDS (passive) and IPS (inline) modes across Linux, macOS, and Windows.
 */
class SnortEngine
{
    private string $snortPath;
    private string $configPath;
    private string $alertLogPath;
    private string $pidFile;
    private string $logDir;

    public function __construct()
    {
        $this->snortPath = $this->detectSnortPath();
        $this->configPath = $this->detectConfigPath();
        $this->logDir = $this->detectLogDir();
        $this->alertLogPath = $this->logDir . '/alert_json.txt';
        $this->pidFile = $this->logDir . '/snort.pid';
    }

    /**
     * Check if Snort is installed on this system
     */
    public function isInstalled(): bool
    {
        return !empty($this->snortPath) && file_exists($this->snortPath);
    }

    /**
     * Get the alert log file path (auto-detects Snort 2 vs Snort 3)
     */
    public function getAlertLogPath(): string
    {
        // Snort 3: alert_json.txt
        if (file_exists($this->alertLogPath)) {
            return $this->alertLogPath;
        }

        // Snort 2: snort.alert.fast (text format)
        $fastAlert = $this->logDir . '/snort.alert.fast';
        if (file_exists($fastAlert)) {
            return $fastAlert;
        }

        return $this->alertLogPath;
    }

    /**
     * Get installed Snort version
     */
    public function getVersion(): ?string
    {
        if (!$this->isInstalled()) {
            return null;
        }

        try {
            $result = Process::run("{$this->snortPath} -V 2>&1");
            $output = $result->output() . $result->errorOutput();

            // Snort 3 outputs: ",,_ -*> Snort++ <*- ... Version 3.x.x.x"
            if (preg_match('/Version\s+([\d.]+)/i', $output, $matches)) {
                return $matches[1];
            }

            // Snort 2 fallback
            if (preg_match('/Snort\s+([\d.]+)/i', $output, $matches)) {
                return $matches[1];
            }
        } catch (\Exception $e) {
            Log::warning('Failed to get Snort version: ' . $e->getMessage());
        }

        return null;
    }

    /**
     * Check if Snort process is currently running
     */
    public function isRunning(): bool
    {
        // Check PID file first
        if (file_exists($this->pidFile)) {
            $pid = trim(file_get_contents($this->pidFile));
            if ($this->isProcessRunning((int) $pid)) {
                return true;
            }
        }

        // Fallback: check process list
        return $this->isSnortProcessActive();
    }

    /**
     * Start Snort in the specified mode
     *
     * @param string $mode 'ids' or 'ips'
     * @param string|null $interface Network interface to monitor
     */
    public function start(string $mode = 'ids', ?string $interface = null): array
    {
        if (!$this->isInstalled()) {
            return ['success' => false, 'error' => 'Snort is not installed'];
        }

        if ($this->isRunning()) {
            return ['success' => true, 'message' => 'Snort is already running'];
        }

        $interface = $interface ?? $this->detectDefaultInterface();

        // Ensure log directory exists with correct permissions
        if (!is_dir($this->logDir)) {
            @mkdir($this->logDir, 0755, true);
        }

        // Build the Snort command (auto-detects Snort 2 vs 3)
        $cmd = $this->buildStartCommand($mode, $interface);

        try {
            Log::info("Starting Snort in {$mode} mode on interface {$interface}", [
                'platform' => PHP_OS_FAMILY,
                'snort_path' => $this->snortPath,
                'command' => $cmd,
            ]);

            if ($this->isWindows()) {
                $result = $this->startSnortWindows($cmd);
            } elseif (PHP_OS === 'Darwin') {
                $result = $this->startSnortMac($cmd);
            } else {
                $result = $this->startSnortLinux($cmd);
            }

            // Wait briefly and check if started
            sleep(2);

            if ($this->isRunning()) {
                Log::info('Snort started successfully', ['platform' => PHP_OS_FAMILY]);
                return ['success' => true, 'message' => "Snort started in {$mode} mode"];
            }

            // Capture error output for debugging
            $errorOutput = $result->errorOutput() ?? '';
            $stdOutput = $result->output() ?? '';
            Log::warning('Snort failed to start', [
                'platform' => PHP_OS_FAMILY,
                'exit_code' => $result->exitCode(),
                'stdout' => substr($stdOutput, 0, 500),
                'stderr' => substr($errorOutput, 0, 500),
            ]);

            return ['success' => false, 'error' => 'Snort started but not running: ' . substr($errorOutput ?: $stdOutput, 0, 200)];
        } catch (\Exception $e) {
            Log::error('Failed to start Snort: ' . $e->getMessage(), [
                'platform' => PHP_OS_FAMILY,
            ]);
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Start Snort on Linux with appropriate privileges
     */
    private function startSnortLinux(string $cmd): \Illuminate\Process\ProcessResult
    {
        // Check if we need sudo (non-root user)
        $needsSudo = function_exists('posix_getuid') && posix_getuid() !== 0;
        $prefix = $needsSudo ? 'sudo ' : '';

        $result = Process::timeout(10)->run("{$prefix}nohup {$cmd} > /dev/null 2>&1 & echo $!");
        $pid = trim($result->output());
        if (is_numeric($pid)) {
            file_put_contents($this->pidFile, $pid);
        }

        return $result;
    }

    /**
     * Start Snort on macOS with sudo for BPF packet capture access
     *
     * macOS requires root/sudo to open BPF devices for raw packet capture.
     * Also tries to fix BPF device permissions as a fallback.
     */
    private function startSnortMac(string $cmd): \Illuminate\Process\ProcessResult
    {
        // First, try to ensure BPF devices are accessible
        $this->ensureBpfAccess();

        // macOS always needs sudo for packet capture
        $result = Process::timeout(10)->run("sudo nohup {$cmd} > /dev/null 2>&1 & echo $!");
        $pid = trim($result->output());
        if (is_numeric($pid)) {
            file_put_contents($this->pidFile, $pid);
        }

        return $result;
    }

    /**
     * Start Snort on Windows with elevated privileges
     *
     * Windows Snort requires Npcap for packet capture.
     * Uses PowerShell to start Snort as a background process with admin rights.
     */
    private function startSnortWindows(string $cmd): \Illuminate\Process\ProcessResult
    {
        // Check for Npcap/WinPcap
        $npcapInstalled = file_exists('C:\\Windows\\System32\\Npcap') ||
                          file_exists('C:\\Program Files\\Npcap') ||
                          file_exists('C:\\Windows\\System32\\wpcap.dll');

        if (!$npcapInstalled) {
            Log::warning('Npcap not detected — Snort may not capture packets. Install from https://npcap.com/');
        }

        // Use PowerShell to start Snort as admin background process
        $escapedCmd = str_replace('"', '`"', $cmd);
        $psCommand = "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c {$escapedCmd}' -WindowStyle Hidden -Verb RunAs";

        return Process::timeout(15)->run("powershell -NonInteractive -Command \"{$psCommand}\"");
    }

    /**
     * Ensure BPF device access on macOS
     *
     * BPF (Berkeley Packet Filter) devices are needed for raw packet capture.
     * This sets permissions so Snort can access them.
     */
    private function ensureBpfAccess(): void
    {
        try {
            // Check if BPF devices exist and are accessible
            if (file_exists('/dev/bpf0') && !is_readable('/dev/bpf0')) {
                // Try to chmod BPF devices (requires sudo)
                Process::timeout(5)->run('sudo chmod 644 /dev/bpf*');
                Log::info('Set BPF device permissions for Snort packet capture');
            }
        } catch (\Exception $e) {
            Log::debug('Could not set BPF permissions: ' . $e->getMessage());
        }
    }

    /**
     * Stop Snort process
     */
    public function stop(): array
    {
        if (!$this->isRunning()) {
            return ['success' => true, 'message' => 'Snort is not running'];
        }

        // On non-Windows, we need sudo since Snort was started with elevated privileges
        $sudo = (!$this->isWindows() && function_exists('posix_getuid') && posix_getuid() !== 0) ? 'sudo ' : '';

        try {
            if (file_exists($this->pidFile)) {
                $pid = trim(file_get_contents($this->pidFile));
                if ($this->isWindows()) {
                    Process::run("taskkill /PID {$pid} /F 2>nul");
                } else {
                    Process::run("{$sudo}kill {$pid} 2>/dev/null");
                    sleep(1);
                    // Force kill if still running
                    if ($this->isProcessRunning((int) $pid)) {
                        Process::run("{$sudo}kill -9 {$pid} 2>/dev/null");
                    }
                }
                @unlink($this->pidFile);
            } else {
                // Kill all snort processes
                if ($this->isWindows()) {
                    Process::run("taskkill /IM snort.exe /F 2>nul");
                } else {
                    Process::run("{$sudo}pkill -f snort 2>/dev/null");
                }
            }

            Log::info('Snort stopped');
            return ['success' => true, 'message' => 'Snort stopped'];
        } catch (\Exception $e) {
            Log::error('Failed to stop Snort: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Get comprehensive Snort status information
     */
    public function getStatus(): array
    {
        $installed = $this->isInstalled();

        return [
            'installed' => $installed,
            'version' => $installed ? $this->getVersion() : null,
            'running' => $installed ? $this->isRunning() : false,
            'path' => $this->snortPath,
            'config_path' => $this->configPath,
            'log_dir' => $this->logDir,
            'stats' => $installed ? $this->getStats() : null,
        ];
    }

    /**
     * Get Snort statistics (packets analyzed, alerts, etc.)
     */
    public function getStats(): array
    {
        $stats = [
            'packets_analyzed' => 0,
            'alerts_total' => 0,
            'alerts_today' => 0,
            'rules_loaded' => 0,
            'uptime' => null,
        ];

        // Count alerts from log file
        if (file_exists($this->alertLogPath)) {
            $stats['alerts_total'] = $this->countLines($this->alertLogPath);
            $stats['alerts_today'] = $this->countAlertsToday();
        }

        // Try to get Snort stats from stats file
        $statsFile = $this->logDir . '/snort.stats';
        if (file_exists($statsFile)) {
            $statsContent = @file_get_contents($statsFile);
            if ($statsContent && preg_match('/total_packets:\s*(\d+)/i', $statsContent, $m)) {
                $stats['packets_analyzed'] = (int) $m[1];
            }
        }

        // Count rules
        $stats['rules_loaded'] = $this->countLoadedRules();

        return $stats;
    }

    /**
     * Parse recent alerts from Snort's JSON alert log
     *
     * @param int $limit Number of alerts to return
     * @return array Parsed alert entries
     */
    public function parseAlerts(int $limit = 50): array
    {
        if (!file_exists($this->alertLogPath)) {
            return [];
        }

        $alerts = [];

        try {
            // Read last N lines efficiently
            $lines = $this->tailFile($this->alertLogPath, $limit);

            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line)) {
                    continue;
                }

                $decoded = json_decode($line, true);
                if (!$decoded) {
                    continue;
                }

                $alerts[] = [
                    'timestamp' => $decoded['timestamp'] ?? $decoded['seconds'] ?? null,
                    'signature' => $decoded['msg'] ?? $decoded['rule'] ?? 'Unknown',
                    'signature_id' => $decoded['sid'] ?? $decoded['gid'] ?? null,
                    'priority' => $decoded['priority'] ?? 3,
                    'severity' => $this->priorityToSeverity($decoded['priority'] ?? 3),
                    'protocol' => $decoded['proto'] ?? $decoded['protocol'] ?? 'unknown',
                    'source_ip' => $decoded['src_addr'] ?? $decoded['src_ap'] ?? null,
                    'source_port' => $decoded['src_port'] ?? null,
                    'dest_ip' => $decoded['dst_addr'] ?? $decoded['dst_ap'] ?? null,
                    'dest_port' => $decoded['dst_port'] ?? null,
                    'classification' => $decoded['class'] ?? $decoded['classtype'] ?? null,
                    'action' => $decoded['action'] ?? 'alert',
                    'raw' => $decoded,
                ];
            }
        } catch (\Exception $e) {
            Log::warning('Failed to parse Snort alerts: ' . $e->getMessage());
        }

        return array_reverse($alerts); // Most recent first
    }

    /**
     * Update Snort rules (community/ET rules)
     */
    public function updateRules(): array
    {
        if (!$this->isInstalled()) {
            return ['success' => false, 'error' => 'Snort is not installed'];
        }

        try {
            Log::info('Updating Snort rules...');

            // Try PulledPork3 first (official rule updater for Snort 3)
            $ppPath = $this->detectPulledPorkPath();
            if ($ppPath) {
                $result = Process::timeout(300)->run("{$ppPath} -c /etc/snort/pulledpork.conf 2>&1");
                if ($result->successful()) {
                    Log::info('Snort rules updated via PulledPork');
                    return ['success' => true, 'method' => 'pulledpork', 'output' => $result->output()];
                }
            }

            // Fallback: download community rules manually
            $rulesDir = $this->detectRulesDir();
            $tempFile = sys_get_temp_dir() . '/snort3-community-rules.tar.gz';
            $url = 'https://www.snort.org/downloads/community/snort3-community-rules.tar.gz';

            if ($this->isWindows()) {
                Process::run("curl -fsSL -o \"{$tempFile}\" \"{$url}\"");
            } else {
                Process::run("wget -q -O '{$tempFile}' '{$url}' 2>/dev/null || curl -fsSL -o '{$tempFile}' '{$url}'");
            }

            if (file_exists($tempFile) && filesize($tempFile) > 1000) {
                if (!$this->isWindows()) {
                    Process::run("tar xzf '{$tempFile}' -C '{$rulesDir}' --strip-components=1 2>/dev/null");
                }
                @unlink($tempFile);

                // Reload Snort if running
                if ($this->isRunning()) {
                    $this->reload();
                }

                Log::info('Snort community rules updated');
                return ['success' => true, 'method' => 'community', 'message' => 'Community rules downloaded'];
            }

            return ['success' => false, 'error' => 'Failed to download rules'];
        } catch (\Exception $e) {
            Log::error('Failed to update Snort rules: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Reload Snort configuration (SIGHUP)
     */
    public function reload(): bool
    {
        if (!$this->isRunning()) {
            return false;
        }

        try {
            if (file_exists($this->pidFile)) {
                $pid = trim(file_get_contents($this->pidFile));
                if (!$this->isWindows()) {
                    Process::run("kill -HUP {$pid}");
                    return true;
                }
            }
        } catch (\Exception $e) {
            Log::warning('Failed to reload Snort: ' . $e->getMessage());
        }

        return false;
    }

    /**
     * Apply custom rules content to Snort
     */
    public function applyCustomRules(string $rulesContent): array
    {
        $customRulesFile = $this->detectRulesDir() . '/local.rules';

        try {
            file_put_contents($customRulesFile, $rulesContent);

            // Reload if running
            if ($this->isRunning()) {
                $this->reload();
            }

            return ['success' => true, 'rules_file' => $customRulesFile];
        } catch (\Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    // ─── Private Helpers ─────────────────────────────────────────

    /**
     * Detect if this is Snort 2.x (vs Snort 3.x)
     * Snort 2 and 3 have different CLI flags.
     */
    private function isSnort2(): bool
    {
        $version = $this->getVersion();
        if (!$version) {
            return false;
        }

        return version_compare($version, '3.0.0', '<');
    }

    /**
     * Build Snort start command, auto-detecting Snort 2 vs 3 flags
     */
    private function buildStartCommand(string $mode, string $interface): string
    {
        $cmd = "{$this->snortPath}";

        if ($this->isSnort2()) {
            return $this->buildSnort2Command($cmd, $mode, $interface);
        }

        return $this->buildSnort3Command($cmd, $mode, $interface);
    }

    /**
     * Build command for Snort 2.9.x
     */
    private function buildSnort2Command(string $cmd, string $mode, string $interface): string
    {
        if (file_exists($this->configPath)) {
            $cmd .= " -c {$this->configPath}";
        }

        $cmd .= " -i {$interface}";
        $cmd .= " -l {$this->logDir}";

        // Snort 2: Use fast alert output (text format parsed by collectSnortAlerts)
        $cmd .= " -A fast";

        if ($mode === 'ips') {
            $cmd .= " -Q"; // Inline/IPS mode
        }

        // Run as daemon on Unix
        if (!$this->isWindows()) {
            $cmd .= " -D";
        }

        return $cmd;
    }

    /**
     * Build command for Snort 3.x
     */
    private function buildSnort3Command(string $cmd, string $mode, string $interface): string
    {
        if (file_exists($this->configPath)) {
            $cmd .= " -c {$this->configPath}";
        }

        $cmd .= " -i {$interface}";
        $cmd .= " -l {$this->logDir}";
        $cmd .= " --alert-before-pass";

        // JSON alert output
        $cmd .= " -A alert_json";

        if ($mode === 'ips') {
            $cmd .= " -Q"; // Inline/IPS mode
        }

        // Run as daemon on Unix
        if (!$this->isWindows()) {
            $cmd .= " -D";
            $cmd .= " --pid-path {$this->logDir}";
        }

        return $cmd;
    }

    private function detectSnortPath(): string
    {
        $paths = $this->isWindows()
            ? [
                'C:\\Snort\\bin\\snort.exe',
                'C:\\Program Files\\Snort\\bin\\snort.exe',
                'C:\\Program Files (x86)\\Snort\\bin\\snort.exe',
            ]
            : [
                '/usr/local/bin/snort',
                '/usr/local/bin/snort3',
                '/usr/sbin/snort',
                '/usr/sbin/snort3',
                '/usr/bin/snort',
                '/usr/bin/snort3',
                '/opt/snort/bin/snort',
                '/opt/homebrew/bin/snort',
            ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        // Try which/where command
        try {
            $cmd = $this->isWindows() ? 'where snort 2>nul' : 'which snort3 2>/dev/null || which snort 2>/dev/null';
            $result = Process::run($cmd);
            $path = trim($result->output());
            if (!empty($path) && file_exists($path)) {
                return $path;
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return '';
    }

    private function detectConfigPath(): string
    {
        $paths = $this->isWindows()
            ? [
                'C:\\Snort\\etc\\snort\\snort.lua',
                'C:\\Snort\\etc\\snort.lua',
                'C:\\Program Files\\Snort\\etc\\snort\\snort.lua',
            ]
            : [
                '/etc/snort/snort.lua',           // Snort 3
                '/usr/local/etc/snort/snort.lua',
                '/opt/snort/etc/snort/snort.lua',
                '/etc/snort/snort.conf',          // Snort 2 fallback
                '/usr/local/etc/snort/snort.conf',
            ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return '/etc/snort/snort.lua';
    }

    private function detectLogDir(): string
    {
        if ($this->isWindows()) {
            $dir = 'C:\\Snort\\log';
        } elseif (PHP_OS === 'Darwin') {
            $dir = '/var/log/snort';
        } else {
            $dir = '/var/log/snort';
        }

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        return $dir;
    }

    private function detectRulesDir(): string
    {
        $paths = $this->isWindows()
            ? ['C:\\Snort\\rules', 'C:\\Snort\\etc\\snort\\rules']
            : ['/etc/snort/rules', '/usr/local/etc/snort/rules', '/opt/snort/rules'];

        foreach ($paths as $path) {
            if (is_dir($path)) {
                return $path;
            }
        }

        $default = $this->isWindows() ? 'C:\\Snort\\rules' : '/etc/snort/rules';
        @mkdir($default, 0755, true);

        return $default;
    }

    private function detectDefaultInterface(): string
    {
        if ($this->isWindows()) {
            return '1'; // Windows uses interface index
        }

        $isMac = PHP_OS === 'Darwin';

        // macOS: try route command first
        if ($isMac) {
            try {
                $result = Process::run("route -n get default 2>/dev/null | grep 'interface:' | awk '{print \$2}'");
                $iface = trim($result->output());
                if (!empty($iface)) {
                    return $iface;
                }
            } catch (\Exception $e) {
                // Ignore
            }

            // macOS fallback: get first active network service interface
            try {
                $result = Process::run("networksetup -listallhardwareports 2>/dev/null | awk '/Device:/{print \$2}' | head -1");
                $iface = trim($result->output());
                if (!empty($iface)) {
                    return $iface;
                }
            } catch (\Exception $e) {
                // Ignore
            }

            return 'en0'; // macOS default
        }

        // Linux: try to find the default interface
        try {
            $result = Process::run("ip route show default 2>/dev/null | awk '{print \$5}' | head -1");
            $iface = trim($result->output());
            if (!empty($iface)) {
                return $iface;
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return 'eth0';
    }

    private function detectPulledPorkPath(): ?string
    {
        $paths = ['/usr/local/bin/pulledpork3.py', '/usr/local/bin/pulledpork.py', '/opt/pulledpork/pulledpork3.py'];
        foreach ($paths as $path) {
            if (file_exists($path)) {
                return "python3 {$path}";
            }
        }

        return null;
    }

    private function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }

    private function isProcessRunning(int $pid): bool
    {
        if ($this->isWindows()) {
            try {
                $result = Process::run("tasklist /FI \"PID eq {$pid}\" /NH 2>nul");
                return str_contains($result->output(), (string) $pid);
            } catch (\Exception $e) {
                return false;
            }
        }

        return file_exists("/proc/{$pid}") || (posix_kill($pid, 0) === true);
    }

    private function isSnortProcessActive(): bool
    {
        try {
            if ($this->isWindows()) {
                $result = Process::run('tasklist /FI "IMAGENAME eq snort.exe" /NH 2>nul');
                return str_contains($result->output(), 'snort');
            }

            $result = Process::run('pgrep -f snort 2>/dev/null');
            return !empty(trim($result->output()));
        } catch (\Exception $e) {
            return false;
        }
    }

    private function priorityToSeverity(int $priority): string
    {
        return match (true) {
            $priority <= 1 => 'critical',
            $priority === 2 => 'high',
            $priority === 3 => 'medium',
            default => 'low',
        };
    }

    private function countLines(string $file): int
    {
        try {
            if ($this->isWindows()) {
                $result = Process::run("find /c /v \"\" \"{$file}\" 2>nul");
                if (preg_match('/(\d+)/', $result->output(), $m)) {
                    return (int) $m[1];
                }
            } else {
                $result = Process::run("wc -l < '{$file}' 2>/dev/null");
                return (int) trim($result->output());
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return 0;
    }

    private function countAlertsToday(): int
    {
        if (!file_exists($this->alertLogPath)) {
            return 0;
        }

        $today = date('Y-m-d');
        $count = 0;

        try {
            $lines = $this->tailFile($this->alertLogPath, 500);
            foreach ($lines as $line) {
                if (str_contains($line, $today)) {
                    $count++;
                }
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return $count;
    }

    private function countLoadedRules(): int
    {
        $rulesDir = $this->detectRulesDir();

        if (!is_dir($rulesDir)) {
            return 0;
        }

        $count = 0;
        $files = glob($rulesDir . '/*.rules');
        foreach ($files ?: [] as $file) {
            $content = @file_get_contents($file);
            if ($content) {
                // Count non-comment, non-empty lines
                $lines = explode("\n", $content);
                foreach ($lines as $line) {
                    $line = trim($line);
                    if (!empty($line) && $line[0] !== '#') {
                        $count++;
                    }
                }
            }
        }

        return $count;
    }

    /**
     * Read last N lines of a file efficiently
     */
    private function tailFile(string $file, int $lines): array
    {
        try {
            if ($this->isWindows()) {
                $result = Process::run("powershell -Command \"Get-Content '{$file}' -Tail {$lines}\"");
            } else {
                $result = Process::run("tail -n {$lines} '{$file}' 2>/dev/null");
            }

            return array_filter(explode("\n", $result->output()));
        } catch (\Exception $e) {
            return [];
        }
    }
}
