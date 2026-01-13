<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Http;

class ClamavService
{
    protected bool $isInstalled = false;
    protected ?string $version = null;
    protected ?string $definitionsDate = null;

    public function __construct()
    {
        $this->checkInstallation();
    }

    /**
     * Check if ClamAV is installed
     */
    public function checkInstallation(): bool
    {
        $platform = $this->getPlatform();
        
        try {
            if ($platform === 'macos') {
                // Check common Homebrew paths for clamscan
                $paths = [
                    '/opt/homebrew/bin/clamscan',
                    '/usr/local/bin/clamscan',
                    '/usr/bin/clamscan',
                ];
                
                foreach ($paths as $path) {
                    if (file_exists($path)) {
                        $this->isInstalled = true;
                        $this->getVersion();
                        return true;
                    }
                }
                
                // Also try which command with Homebrew PATH
                $result = Process::run('export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" && which clamscan');
                $this->isInstalled = $result->successful() && !empty(trim($result->output()));
            } else {
                $result = Process::run('which clamscan 2>/dev/null || command -v clamscan 2>/dev/null');
                $this->isInstalled = $result->successful() && !empty(trim($result->output()));
            }
            
            if ($this->isInstalled) {
                $this->getVersion();
            }
            
            return $this->isInstalled;
        } catch (\Exception $e) {
            Log::error('ClamAV check failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get ClamAV version
     */
    public function getVersion(): ?string
    {
        if ($this->version) {
            return $this->version;
        }

        try {
            // Use full PATH for macOS Homebrew compatibility
            $cmd = $this->getPlatform() === 'macos'
                ? 'export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" && clamscan --version'
                : 'clamscan --version';
            
            $result = Process::run($cmd);
            if ($result->successful()) {
                $output = trim($result->output());
                // Extract version: "ClamAV 0.103.6/26589/Wed Jul  3 07:32:13 2024"
                if (preg_match('/ClamAV\s+([\d.]+)/', $output, $matches)) {
                    $this->version = $matches[1];
                } else {
                    $this->version = $output;
                }
            }
        } catch (\Exception $e) {
            Log::error('Failed to get ClamAV version: ' . $e->getMessage());
        }

        return $this->version;
    }

    /**
     * Get virus definitions date
     */
    public function getDefinitionsDate(): ?string
    {
        try {
            $result = Process::run('clamscan --version');
            if ($result->successful()) {
                $output = trim($result->output());
                // Extract date from: "ClamAV 0.103.6/26589/Wed Jul  3 07:32:13 2024"
                if (preg_match('/\/(\d+)\/(.+)$/', $output, $matches)) {
                    $this->definitionsDate = $matches[2];
                    return $this->definitionsDate;
                }
            }
        } catch (\Exception $e) {
            Log::error('Failed to get definitions date: ' . $e->getMessage());
        }

        return null;
    }

    /**
     * Install ClamAV (platform-specific)
     */
    public function install(): array
    {
        $platform = $this->getPlatform();
        
        Log::info('Installing ClamAV on ' . $platform);

        try {
            switch ($platform) {
                case 'macos':
                    return $this->installMacos();
                case 'alpine':
                    return $this->installAlpine();
                case 'linux':
                case 'ubuntu':
                case 'debian':
                    return $this->installDebian();
                case 'rhel':
                case 'centos':
                case 'fedora':
                    return $this->installRhel();
                default:
                    return [
                        'success' => false,
                        'message' => "Unsupported platform: {$platform}",
                    ];
            }
        } catch (\Exception $e) {
            Log::error('ClamAV installation failed: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Install on macOS using Homebrew
     */
    protected function installMacos(): array
    {
        // Check if Homebrew is installed
        $brewCheck = Process::run('which brew');
        if (!$brewCheck->successful()) {
            return [
                'success' => false,
                'message' => 'Homebrew not installed. Please install Homebrew first.',
            ];
        }

        // Install ClamAV
        $result = Process::timeout(300)->run('brew install clamav');
        
        if (!$result->successful()) {
            return [
                'success' => false,
                'message' => 'Failed to install ClamAV: ' . $result->errorOutput(),
            ];
        }

        // Initialize freshclam configuration
        $this->initializeFreshclam();

        // Update virus definitions
        $this->updateDefinitions();

        $this->isInstalled = true;
        
        return [
            'success' => true,
            'message' => 'ClamAV installed successfully on macOS',
        ];
    }

    /**
     * Install on Debian/Ubuntu
     */
    protected function installDebian(): array
    {
        $result = Process::timeout(300)->run('sudo apt-get update && sudo apt-get install -y clamav clamav-daemon');
        
        if (!$result->successful()) {
            return [
                'success' => false,
                'message' => 'Failed to install ClamAV: ' . $result->errorOutput(),
            ];
        }

        // Update virus definitions
        Process::run('sudo systemctl stop clamav-freshclam');
        $this->updateDefinitions();
        Process::run('sudo systemctl start clamav-freshclam');

        $this->isInstalled = true;
        
        return [
            'success' => true,
            'message' => 'ClamAV installed successfully on Debian/Ubuntu',
        ];
    }

    /**
     * Install on Alpine Linux (Docker)
     */
    protected function installAlpine(): array
    {
        // Alpine uses apk package manager
        $result = Process::timeout(300)->run('apk add --no-cache clamav clamav-libunrar');
        
        if (!$result->successful()) {
            return [
                'success' => false,
                'message' => 'Failed to install ClamAV: ' . $result->errorOutput(),
            ];
        }

        // Create database directory and update definitions
        Process::run('mkdir -p /var/lib/clamav');
        $this->updateDefinitions();

        $this->isInstalled = true;
        
        return [
            'success' => true,
            'message' => 'ClamAV installed successfully on Alpine Linux',
        ];
    }

    /**
     * Install on RHEL/CentOS/Fedora
     */
    protected function installRhel(): array
    {
        // Try dnf first, fallback to yum
        $dnfCheck = Process::run('which dnf');
        $pm = $dnfCheck->successful() ? 'dnf' : 'yum';

        $result = Process::timeout(300)->run("sudo {$pm} install -y clamav clamav-update clamd");
        
        if (!$result->successful()) {
            return [
                'success' => false,
                'message' => 'Failed to install ClamAV: ' . $result->errorOutput(),
            ];
        }

        $this->updateDefinitions();
        $this->isInstalled = true;
        
        return [
            'success' => true,
            'message' => 'ClamAV installed successfully on RHEL/CentOS',
        ];
    }

    /**
     * Initialize freshclam configuration
     */
    protected function initializeFreshclam(): void
    {
        $platform = $this->getPlatform();
        
        if ($platform === 'macos') {
            // Create freshclam.conf from sample if not exists
            $confPath = '/opt/homebrew/etc/clamav/freshclam.conf';
            $samplePath = '/opt/homebrew/etc/clamav/freshclam.conf.sample';
            
            if (!file_exists($confPath) && file_exists($samplePath)) {
                Process::run("cp {$samplePath} {$confPath}");
                // Comment out Example line
                Process::run("sed -i '' 's/^Example/#Example/' {$confPath}");
            }
        }
    }

    /**
     * Update virus definitions
     */
    public function updateDefinitions(): array
    {
        Log::info('Updating ClamAV virus definitions');

        try {
            $result = Process::timeout(600)->run('sudo freshclam');
            
            if ($result->successful()) {
                return [
                    'success' => true,
                    'message' => 'Virus definitions updated successfully',
                ];
            }

            return [
                'success' => false,
                'message' => 'Failed to update definitions: ' . $result->errorOutput(),
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Scan a directory
     */
    public function scan(string $path = '/'): array
    {
        if (!$this->isInstalled) {
            return [
                'success' => false,
                'status' => 'not_installed',
                'message' => 'ClamAV is not installed',
            ];
        }

        Log::info('Starting ClamAV scan on: ' . $path);

        try {
            // Build command with proper PATH for macOS Homebrew
            $pathPrefix = $this->getPlatform() === 'macos' 
                ? 'export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" && '
                : '';
            
            // Run clamscan with recursive option and get summary
            // Capture stderr for debugging - some permission errors may occur but scan will continue
            $scanCmd = "{$pathPrefix}clamscan -r {$path} 2>&1";
            $result = Process::timeout(7200)->run($scanCmd);
            
            // Log if there was an error
            if (!$result->successful()) {
                Log::warning('ClamAV scan command returned non-zero', [
                    'exit_code' => $result->exitCode(),
                    'error_output' => substr($result->errorOutput(), 0, 500),
                ]);
            }
            
            $output = $result->output();
            $infected = [];
            $scannedFiles = 0;
            $infectedCount = 0;

            // Parse output for infected files
            $lines = explode("\n", trim($output));
            foreach ($lines as $line) {
                if (str_contains($line, ' FOUND')) {
                    $infected[] = trim(str_replace(' FOUND', '', $line));
                }
                // Look for scan summary in output
                if (preg_match('/Scanned files:\s*(\d+)/i', $line, $matches)) {
                    $scannedFiles = (int) $matches[1];
                }
                if (preg_match('/Infected files:\s*(\d+)/i', $line, $matches)) {
                    $infectedCount = (int) $matches[1];
                }
            }

            Log::info('ClamAV scan completed', [
                'path' => $path,
                'scanned_files' => $scannedFiles,
                'infected_files' => max(count($infected), $infectedCount),
            ]);

            return [
                'success' => true,
                'status' => count($infected) > 0 ? 'warning' : 'healthy',
                'scanned_files' => $scannedFiles,
                'infected_files' => max(count($infected), $infectedCount),
                'threats' => $infected,
            ];
        } catch (\Exception $e) {
            Log::error('ClamAV scan failed: ' . $e->getMessage());
            return [
                'success' => false,
                'status' => 'error',
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Get current status
     */
    public function getStatus(): array
    {
        return [
            'installed' => $this->isInstalled,
            'version' => $this->getVersion(),
            'definitions_date' => $this->getDefinitionsDate(),
            'status' => $this->isInstalled ? 'healthy' : 'not_installed',
        ];
    }

    /**
     * Report status to WAF Hub
     */
    public function reportToHub(array $scanResult = []): bool
    {
        try {
            $wafUrl = rtrim(config('ids.waf_url') ?? env('WAF_URL', ''), '/');
            
            // Read token directly from .env to avoid cache/database issues
            $envPath = base_path('.env');
            $token = env('AGENT_TOKEN', '');
            
            // Also try reading .env file directly if env() doesn't work
            if (empty($token) && file_exists($envPath)) {
                $envContent = file_get_contents($envPath);
                if (preg_match('/^AGENT_TOKEN=(.*)$/m', $envContent, $matches)) {
                    $token = trim($matches[1], '"\'');
                }
            }

            Log::info('ClamAV reportToHub: attempting to report status', [
                'waf_url' => $wafUrl,
                'has_token' => !empty($token),
            ]);

            if (empty($wafUrl) || empty($token)) {
                Log::warning('Cannot report ClamAV status: WAF not configured', [
                    'waf_url_empty' => empty($wafUrl),
                    'token_empty' => empty($token),
                ]);
                return false;
            }

            $status = $this->getStatus();
            
            $payload = [
                'version' => $status['version'],
                'definitions_date' => $this->parseDefinitionsDate($status['definitions_date']),
                'last_scan' => $scanResult['last_scan'] ?? null,
                'infected_files' => $scanResult['infected_files'] ?? 0,
                'scanned_files' => $scanResult['scanned_files'] ?? 0,
                'threats' => $scanResult['threats'] ?? [],
                'status' => $scanResult['status'] ?? $status['status'],
                'scan_progress' => $scanResult['scan_progress'] ?? null,
                'scan_completed' => $scanResult['scan_completed'] ?? false,
                'skip_scan_status' => $scanResult['skip_scan_status'] ?? false,  // Skip updating scan_status if true
                'error_message' => $scanResult['message'] ?? null,
            ];
            
            // ALWAYS send real scan_status - detect if clamscan is running
            // This replaces the old skip_scan_status logic which was unreliable
            if (isset($scanResult['scan_status'])) {
                // Explicit status from RunScan - use it
                $payload['scan_status'] = $scanResult['scan_status'];
            } else {
                // Heartbeat - detect actual status and directory from clamscan process
                $scanProgress = $this->getScanProgress();
                $isScanning = $scanProgress !== null;
                $payload['scan_status'] = $isScanning ? 'scanning' : 'idle';
                
                // Use actual scan progress from ps command (shows current directory)
                if ($isScanning && empty($payload['scan_progress'])) {
                    $payload['scan_progress'] = $scanProgress;
                }
            }

            // Log full payload for debugging
            Log::info('ClamAV reportToHub: sending payload', [
                'scanned_files' => $payload['scanned_files'],
                'infected_files' => $payload['infected_files'],
                'last_scan' => $payload['last_scan'],
                'scan_status' => $payload['scan_status'],
                'scan_progress' => $payload['scan_progress'],
            ]);

            $response = Http::timeout(30)
                ->withToken($token)
                ->post("{$wafUrl}/api/ids/agents/clamav-status", $payload);

            if ($response->successful()) {
                Log::info('ClamAV status reported successfully');
                return true;
            }

            Log::error('ClamAV reportToHub failed', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return false;
        } catch (\Exception $e) {
            Log::error('Failed to report ClamAV status: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Parse definitions date string to date format
     */
    protected function parseDefinitionsDate(?string $dateStr): ?string
    {
        if (!$dateStr) {
            return null;
        }

        try {
            $date = new \DateTime($dateStr);
            return $date->format('Y-m-d');
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Detect platform
     */
    protected function getPlatform(): string
    {
        if (stripos(PHP_OS, 'Darwin') !== false) {
            return 'macos';
        }

        if (stripos(PHP_OS, 'Linux') !== false) {
            // Detect Linux distribution
            // Check Alpine first (Docker containers typically use Alpine)
            if (file_exists('/etc/alpine-release')) {
                return 'alpine';
            }
            if (file_exists('/etc/debian_version')) {
                return 'debian';
            }
            if (file_exists('/etc/redhat-release')) {
                return 'rhel';
            }
            return 'linux';
        }

        return 'unknown';
    }

    /**
     * Check if ClamAV is installed
     */
    public function isInstalled(): bool
    {
        return $this->isInstalled;
    }

    /**
     * Check if a clamscan process is currently running
     * This is used to detect real-time scan status
     */
    public function isScanRunning(): bool
    {
        return $this->getScanProgress() !== null;
    }

    /**
     * Get current scan progress by checking clamscan process
     * Returns the directory being scanned, or null if not scanning
     */
    public function getScanProgress(): ?string
    {
        try {
            // Get full command line of clamscan process
            if (PHP_OS_FAMILY === 'Darwin') {
                // macOS: use ps to get full command
                $result = Process::run('ps aux | grep -v grep | grep "clamscan -r"');
            } else {
                // Linux: use ps to get full command
                $result = Process::run('ps aux | grep -v grep | grep "clamscan"');
            }
            
            if ($result->successful() && !empty(trim($result->output()))) {
                $output = trim($result->output());
                // Parse command line to extract directory
                // Example: "clamscan -r /Library" -> extract "/Library"
                if (preg_match('/clamscan\s+(?:-\w+\s+)*-r\s+(\S+)/', $output, $matches)) {
                    return "掃描中: " . $matches[1];
                }
                if (preg_match('/clamscan\s+(?:-\w+\s+)*(\S+)/', $output, $matches)) {
                    return "掃描中: " . $matches[1];
                }
                return "掃描中...";
            }
            
            return null;
        } catch (\Exception $e) {
            return null;
        }
    }
}
