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
                $result = Process::run('which clamscan');
            } else {
                $result = Process::run('which clamscan 2>/dev/null || command -v clamscan 2>/dev/null');
            }
            
            $this->isInstalled = $result->successful() && !empty(trim($result->output()));
            
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
            $result = Process::run('clamscan --version');
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
            // Run clamscan with recursive option
            $result = Process::timeout(3600)->run("clamscan -r --infected --no-summary {$path} 2>/dev/null | head -100");
            
            $output = $result->output();
            $infected = [];
            $scannedFiles = 0;

            // Parse output for infected files
            $lines = explode("\n", trim($output));
            foreach ($lines as $line) {
                if (str_contains($line, ' FOUND')) {
                    $infected[] = trim(str_replace(' FOUND', '', $line));
                }
            }

            // Get scan summary
            $summaryResult = Process::run("clamscan -r {$path} 2>/dev/null | tail -10");
            if (preg_match('/Scanned files:\s*(\d+)/', $summaryResult->output(), $matches)) {
                $scannedFiles = (int) $matches[1];
            }

            return [
                'success' => true,
                'status' => count($infected) > 0 ? 'warning' : 'healthy',
                'scanned_files' => $scannedFiles,
                'infected_files' => count($infected),
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
            
            // Use same token retrieval pattern as WafSyncService
            $cachedToken = cache()->get('waf_agent_token');
            $envToken = config('ids.agent_token') ?? env('AGENT_TOKEN', '');
            $token = !empty($cachedToken) ? $cachedToken : $envToken;

            Log::info('ClamAV reportToHub: attempting to report status', [
                'waf_url' => $wafUrl,
                'has_token' => !empty($token),
                'token_source' => !empty($cachedToken) ? 'cache' : 'env',
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
                'status' => $status['status'],
                'error_message' => $scanResult['message'] ?? null,
            ];

            Log::info('ClamAV reportToHub: sending payload', [
                'status' => $status['status'],
                'version' => $status['version'],
                'installed' => $status['installed'],
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
}
