<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Artisan;

class WafSyncService
{
    protected string $wafUrl;
    protected string $agentToken;
    protected string $agentName;
    protected bool $codeUpdated = false;

    public function __construct()
    {
        $this->wafUrl = rtrim(config('ids.waf_url') ?? env('WAF_URL', ''), '/');
        
        // Prefer cached WAF-assigned token over .env token (registration returns correct token)
        $cachedToken = cache()->get('waf_agent_token');
        $envToken = config('ids.agent_token') ?? env('AGENT_TOKEN', '');
        $this->agentToken = !empty($cachedToken) ? $cachedToken : $envToken;
        
        $this->agentName = config('ids.agent_name') ?? env('AGENT_NAME', gethostname());
    }

    /**
     * Get HTTP client with SSL configuration for Windows
     */
    protected function getHttpClient(int $timeout = 30): \Illuminate\Http\Client\PendingRequest
    {
        $http = Http::timeout($timeout)
            ->withHeaders([
                'Content-Type' => 'application/json; charset=utf-8',
                'Accept' => 'application/json',
            ]);
        
        // On Windows, configure SSL certificate path at runtime
        if (PHP_OS_FAMILY === 'Windows') {
            $cacertPath = $this->getCaCertPath();
            if ($cacertPath) {
                $http = $http->withOptions([
                    'verify' => $cacertPath,
                ]);
            }
        }
        
        return $http;
    }

    /**
     * Register this agent with the central WAF
     */
    public function register(): bool
    {
        // Debug logging
        Log::debug('WafSync register() called', [
            'wafUrl' => $this->wafUrl,
            'agentToken' => substr($this->agentToken, 0, 10) . '...',
            'agentName' => $this->agentName,
        ]);

        if (empty($this->wafUrl) || empty($this->agentToken)) {
            Log::warning('WAF_URL or AGENT_TOKEN not configured', [
                'wafUrl_empty' => empty($this->wafUrl),
                'agentToken_empty' => empty($this->agentToken),
                'env_WAF_URL' => env('WAF_URL'),
                'config_ids.waf_url' => config('ids.waf_url'),
            ]);
            return false;
        }

        try {
            $response = $this->getHttpClient(30)->post("{$this->wafUrl}/api/ids/agents/register", [
                'token' => $this->agentToken,
                'name' => $this->agentName,
                'ip_address' => $this->getPublicIp(),
                'hostname' => gethostname(),
                'version' => config('app.version', '1.0.0'),
                'platform' => $this->detectPlatform(),
                'system_info' => $this->getSystemInfo(),
            ]);

            if ($response->successful()) {
                $data = $response->json();
                Log::info('Successfully registered with WAF', $data);
                
                // Store the WAF-assigned token for future use
                if (!empty($data['token'])) {
                    cache()->put('waf_agent_token', $data['token'], now()->addDays(30));
                }
                
                // Store the agent ID for alert syncing
                if (!empty($data['agent_id'])) {
                    cache()->put('ids_agent_id', $data['agent_id'], now()->addDays(30));
                }
                
                return true;
            }

            Log::error('Failed to register with WAF', [
                'status' => $response->status(),
                'body' => $response->body(),
                'headers' => $response->headers(),
            ]);
            return false;
        } catch (\Exception $e) {
            Log::error('Exception during WAF registration', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            return false;
        }
    }

    /**
     * Send heartbeat to WAF
     */
    public function heartbeat(): bool
    {
        if (empty($this->wafUrl) || empty($this->agentToken)) {
            Log::warning('WAF_URL or AGENT_TOKEN not configured for heartbeat');
            return false;
        }

        $maxRetries = 3;
        $retryDelay = 2; // seconds
        
        for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
            try {
                $response = $this->getHttpClient(30)->post("{$this->wafUrl}/api/ids/agents/heartbeat", [
                    'token' => $this->agentToken,
                    'name' => $this->agentName,
                    'version' => config('app.version', '1.0.0'),
                    'version_updated_at' => $this->getLastGitPullTime(),
                    'system_info' => $this->getSystemInfo(),
                    'discovered_logs' => $this->getDiscoveredLogPaths(),
                ]);

                if ($response->successful()) {
                    $data = $response->json();
                    Log::debug('Heartbeat sent successfully', $data);
                    
                    // Sync config from WAF Hub (including Ollama settings)
                    if (isset($data['config'])) {
                        $this->syncConfigFromHub($data['config']);
                    }
                    
                    return true;
                }

                // If agent not found (404), try to register
                if ($response->status() === 404) {
                    Log::info('Agent not found, attempting registration...');
                    return $this->register();
                }

                Log::warning('Heartbeat failed', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                    'attempt' => $attempt,
                ]);
                
            } catch (\Exception $e) {
                Log::error("Heartbeat exception (attempt {$attempt}/{$maxRetries}): " . $e->getMessage());
                
                if ($attempt < $maxRetries) {
                    Log::info("Retrying heartbeat in {$retryDelay} seconds...");
                    sleep($retryDelay);
                    continue;
                }
                
                // On final failure, log connection error
                if (str_contains($e->getMessage(), 'Connection') || str_contains($e->getMessage(), 'cURL')) {
                    Log::info('Connection error, will try registration on next sync');
                }
            }
        }
        
        return false;
    }

    /**
     * Sync config received from WAF Hub (save only, tasks dispatched by sub-commands)
     */
    private function syncConfigFromHub(array $config): void
    {
        $configPath = storage_path('app/waf_config.json');
        
        // Read existing config
        $existingConfig = [];
        if (file_exists($configPath)) {
            $existingConfig = json_decode(file_get_contents($configPath), true) ?: [];
        }
        
        // Merge with new config
        $mergedConfig = array_merge($existingConfig, $config);
        
        // Save to storage
        file_put_contents($configPath, json_encode($mergedConfig, JSON_PRETTY_PRINT));
        
        Log::info('Config synced from WAF Hub', [
            'ollama_url' => $config['ollama']['url'] ?? 'not set',
            'ollama_model' => $config['ollama']['model'] ?? 'not set',
            'clamav_enabled' => $config['addons']['clamav_enabled'] ?? false,
            'snort_enabled' => $config['addons']['snort_enabled'] ?? false,
            'snort_mode' => $config['addons']['snort_mode'] ?? 'ids',
            'update_ids' => $config['addons']['update_ids'] ?? false,
            'update_definitions' => $config['addons']['update_definitions'] ?? false,
            'scan_now' => $config['addons']['scan_now'] ?? false,
            'scan_type' => $config['addons']['scan_type'] ?? 'quick',
        ]);
    }

    /**
     * Get saved WAF config from storage
     */
    public function getWafConfig(): array
    {
        $configPath = storage_path('app/waf_config.json');
        if (!file_exists($configPath)) {
            return [];
        }

        return json_decode(file_get_contents($configPath), true) ?: [];
    }

    /**
     * Run quick sync tasks: rules, signatures, alerts, blocked IPs
     */
    public function runQuickSync(): void
    {
        $config = $this->getWafConfig();
        $addons = $config['addons'] ?? [];

        // Snort rules & alerts (only if Snort enabled)
        if (!empty($addons['snort_enabled'])) {
            if (!empty($addons['snort_rules_hash'])) {
                $this->syncSnortRules($addons['snort_rules_hash'], $addons['snort_mode'] ?? 'ids');
            }
            $this->uploadSnortRulesToHub();
            $this->collectSnortAlerts();
        }

        // Blocked IPs
        if (!empty($config['blocked_ips'])) {
            $this->handleBlockedIps($config['blocked_ips']);
        }

        // Fetch rules from WAF and sync to local DB
        $rules = $this->fetchRules();
        if ($rules && isset($rules['rules']) && count($rules['rules']) > 0) {
            $synced = $this->syncRulesToDatabase($rules['rules']);
            Log::info("Synced {$synced} rules from WAF to local database");
            cache()->put('ids_rules', $rules['rules'], now()->addHour());
        }

        // Upload local signatures
        $this->uploadSignatures();
    }

    /**
     * Run Snort management tasks: install, Npcap, start, auto-update
     */
    public function runSnortSync(): void
    {
        $config = $this->getWafConfig();
        $addons = $config['addons'] ?? [];

        if (empty($addons['snort_enabled'])) {
            return;
        }

        $this->handleSnortAddon($addons['snort_mode'] ?? 'ids');
    }

    /**
     * Run maintenance tasks: ClamAV, updates, definitions, scan, system signals
     */
    public function runMaintenanceSync(): void
    {
        $config = $this->getWafConfig();
        $addons = $config['addons'] ?? [];

        // ClamAV
        if (!empty($addons['clamav_enabled'])) {
            $this->handleClamavAddon();
        }

        // IDS update (manual or auto)
        if (!empty($addons['update_ids'])) {
            $this->handleIdsUpdate();
        } else {
            $this->checkAndAutoUpdate();
        }

        // Virus definitions update
        if (!empty($addons['update_definitions'])) {
            $this->handleDefinitionsUpdate();
        }

        // Scan now
        if (!empty($addons['scan_now'])) {
            $this->handleScanNow();
        }

        // System signals (reboot, lock, unlock, login controls)
        if (!empty($addons['reboot'])) {
            Log::warning('Reboot signal received from WAF Hub');
            $this->handleSystemReboot();
        }

        if (!empty($addons['lock'])) {
            Log::warning('Lock signal received from WAF Hub');
            $this->handleSystemLock();
        }

        if (!empty($addons['unlock'])) {
            Log::warning('Unlock signal received from WAF Hub');
            $this->handleSystemUnlock();
        }

        if (!empty($addons['disable_login'])) {
            Log::warning('Disable login signal received from WAF Hub');
            $this->handleDisableLogin();
        }

        if (!empty($addons['enable_login'])) {
            Log::warning('Enable login signal received from WAF Hub');
            $this->handleEnableLogin();
        }
    }
    
    /**
     * Handle ClamAV add-on installation
     */
    private function handleClamavAddon(): void
    {
        try {
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::info('ClamAV enabled but not installed, starting installation...');
                $result = $clamav->install();
                
                if ($result['success']) {
                    Log::info('ClamAV installed successfully');
                } else {
                    Log::error('ClamAV installation failed: ' . ($result['message'] ?? 'Unknown error'));
                }
            }
            
            // Report status to Hub - but don't include scan_status to avoid overwriting active scan
            $status = $clamav->getStatus();
            $status['skip_scan_status'] = true;  // Flag to tell Hub to not update scan_status
            $clamav->reportToHub($status);
            
        } catch (\Exception $e) {
            Log::error('ClamAV addon handling failed: ' . $e->getMessage());
        }
    }

    /**
     * Handle Snort IPS add-on installation and management
     *
     * Called when Hub sends snort_enabled=true in config sync.
     * Existing agents receive this during heartbeat and auto-install Snort.
     */
    private function handleSnortAddon(string $mode = 'ids'): void
    {
        try {
            $snort = app(\App\Services\Detection\SnortEngine::class);

            if (!$snort->isInstalled()) {
                // Check if install already failed — don't retry every heartbeat
                $failFile = storage_path('app/snort_install_failed.txt');
                if (file_exists($failFile)) {
                    $failedAt = filemtime($failFile);
                    // Only retry after 24 hours
                    if (time() - $failedAt < 86400) {
                        Log::debug('Snort install previously failed, skipping retry until ' . date('Y-m-d H:i:s', $failedAt + 86400));
                        return;
                    }
                    // 24h passed — allow retry
                    @unlink($failFile);
                }

                Log::info('Snort enabled but not installed, starting installation...');
                $result = $this->installSnort();

                if ($result['success']) {
                    Log::info('Snort installed successfully');
                    @unlink($failFile); // Clear failure flag
                    $this->reportAgentEvent('snort_install', 'Snort 安裝成功', [
                        'version' => $result['version'] ?? null,
                    ]);
                } else {
                    $error = $result['error'] ?? 'Unknown error';
                    Log::error('Snort installation failed: ' . $error);
                    // Cache the failure to prevent retry every heartbeat
                    file_put_contents($failFile, $error);
                    $this->reportAgentEvent('error', 'Snort 安裝失敗：' . $error);
                    return;
                }

                // Re-instantiate after install
                $snort = new \App\Services\Detection\SnortEngine();
            }

            // Fix: if Snort 3 is running but not writing alert files, restart with --lua config
            if ($snort->isRunning() && !$snort->isSnort2()) {
                $alertFile = $snort->getAlertLogPath();
                $restartMarker = storage_path('app/snort_alert_restart_done.txt');
                if (!file_exists($alertFile) && !file_exists($restartMarker)) {
                    Log::info('Snort 3 running without alert file output, restarting with --lua alert_json config');
                    file_put_contents($restartMarker, date('c'));
                    $snort->stop();
                    sleep(2);
                    // Fall through to start with new --lua config below
                }
            }

            // Start Snort if not running
            if (!$snort->isRunning()) {
                // On Snort 3: skip start if hub_custom.rules doesn't exist yet
                // syncSnortRules() will create converted rules and then start Snort
                $hubRulesFile = $snort->detectRulesDir() . '/hub_custom.rules';
                if (!$snort->isSnort2() && !file_exists($hubRulesFile)) {
                    Log::info('Deferring Snort 3 start until rules sync creates hub_custom.rules');
                } else {
                    $this->ensureNpcapInstalled();
                    $startResult = $snort->startWithRetry($mode);
                    if (!($startResult['success'] ?? false)) {
                        Log::warning('Snort start result', $startResult);
                    } else {
                        Log::info('Snort started successfully');
                        $this->reportAgentEvent('snort_started', "Snort 已啟動（模式：{$mode}）");
                    }
                }
            }

            // Auto-update: check once per day
            $this->autoUpdateSnort($snort);

            // Report status back to Hub via heartbeat
            $status = $snort->getStatus();
            Log::info('Snort status reported', $status);

        } catch (\Exception $e) {
            Log::error('Snort addon handling failed: ' . $e->getMessage());
            $this->reportAgentEvent('error', 'Snort 處理失敗：' . $e->getMessage());
        }
    }

    /**
     * Auto-update Snort (checks once per day)
     */
    private function autoUpdateSnort(\App\Services\Detection\SnortEngine $snort): void
    {
        $updateFile = storage_path('app/snort_last_update_check.txt');

        // Only check once per day
        if (file_exists($updateFile)) {
            $lastCheck = (int) file_get_contents($updateFile);
            if (time() - $lastCheck < 86400) {
                return;
            }
        }

        // Mark as checked
        file_put_contents($updateFile, (string) time());

        try {
            Log::info('Running daily Snort auto-update check...');
            $result = $snort->updateSnort();

            if ($result['success'] ?? false) {
                $version = $result['version'] ?? 'unknown';
                $previous = $result['previous'] ?? null;

                if ($previous && $previous !== $version) {
                    Log::info("Snort updated: {$previous} → {$version}");
                    $this->reportAgentEvent('snort_updated', "Snort 已更新：{$previous} → {$version}", [
                        'old_version' => $previous,
                        'new_version' => $version,
                    ]);
                } else {
                    Log::info("Snort is up to date: {$version}");
                }
            }
        } catch (\Exception $e) {
            Log::warning('Snort auto-update check failed: ' . $e->getMessage());
        }
    }

    /**
     * Install Snort 3 on the current platform
     */
    private function installSnort(): array
    {
        $platform = $this->detectPlatform();
        Log::info("Installing Snort 3 on {$platform}...");

        try {
            switch ($platform) {
                case 'macos':
                    // Find brew path (may not be in PATH for daemon)
                    $brewPath = 'brew';
                    foreach (['/opt/homebrew/bin/brew', '/usr/local/bin/brew'] as $bp) {
                        if (file_exists($bp)) {
                            $brewPath = $bp;
                            break;
                        }
                    }
                    
                    // Homebrew refuses to run as root — detect the real user
                    $brewPrefix = '';
                    if (posix_getuid() === 0) {
                        // Find the actual user: SUDO_USER, or owner of brew binary
                        $realUser = getenv('SUDO_USER') ?: '';
                        if (empty($realUser) && $brewPath !== 'brew') {
                            $ownerInfo = posix_getpwuid(fileowner($brewPath));
                            $realUser = $ownerInfo['name'] ?? '';
                        }
                        if (empty($realUser)) {
                            // Last resort: find first non-root user in /Users
                            $users = @scandir('/Users') ?: [];
                            foreach ($users as $u) {
                                if ($u !== '.' && $u !== '..' && $u !== 'Shared' && $u !== '.localized') {
                                    $realUser = $u;
                                    break;
                                }
                            }
                        }
                        if (!empty($realUser)) {
                            $brewPrefix = "sudo -u {$realUser} ";
                            $home = "/Users/{$realUser}";
                        } else {
                            Log::error('Cannot determine non-root user for Homebrew');
                            return ['success' => false, 'error' => 'Cannot run Homebrew as root. No non-root user found.'];
                        }
                    } else {
                        $home = getenv('HOME') ?: posix_getpwuid(posix_getuid())['dir'] ?? '/tmp';
                    }
                    
                    $brewCmd = "{$brewPrefix}HOME={$home} {$brewPath}";
                    
                    // First ensure Homebrew is up to date
                    Process::timeout(120)->run("{$brewCmd} update 2>&1");
                    
                    // Install required dependencies for Snort 3
                    Log::info('Installing Snort dependencies via Homebrew...');
                    Process::timeout(600)->run("{$brewCmd} install daq libdnet openssl pcre libtool luajit hwloc cmake pkg-config libpcap 2>&1");
                    
                    // Install Snort 3 (the formula is "snort", not "snort3")
                    $result = Process::timeout(600)->run("{$brewCmd} install snort 2>&1");
                    if (!$result->successful()) {
                        // Try MacPorts as fallback
                        $portsCheck = Process::run('which port 2>&1');
                        if ($portsCheck->successful()) {
                            $result = Process::timeout(600)->run('sudo port install snort3 2>&1');
                        }
                    }
                    if (!$result->successful()) {
                        return ['success' => false, 'error' => 'macOS Snort install failed: ' . $result->output() . ' Please install manually: https://www.snort.org/downloads'];
                    }
                    break;

                case 'debian':
                case 'ubuntu':
                    $this->preseedSnortDebconf();
                    Process::run('apt-get update -qq 2>&1');
                    $result = Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y snort 2>&1');
                    // If Snort not in repos, try snap
                    if (!$result->successful()) {
                        $result = Process::timeout(600)->run('snap install snort 2>&1');
                    }
                    break;

                case 'redhat':
                case 'centos':
                    Process::run('yum install -y epel-release 2>&1');
                    $result = Process::timeout(600)->run('yum install -y snort 2>&1');
                    break;

                case 'server':  // Docker containers (Linux-based)
                case 'linux':
                    // Auto-detect Linux distro from /etc/os-release
                    $distro = 'unknown';
                    if (file_exists('/etc/os-release')) {
                        $osRelease = file_get_contents('/etc/os-release');
                        if (preg_match('/^ID=(.+)$/m', $osRelease, $m)) {
                            $distro = strtolower(trim($m[1], '"'));
                        }
                    }

                    Log::info("Linux distro detected: {$distro}");

                    if (in_array($distro, ['debian', 'ubuntu', 'linuxmint', 'pop', 'kali'])) {
                        // Pre-seed debconf to avoid interactive prompts (Snort asks for HOME_NET)
                        $this->preseedSnortDebconf();
                        Process::run('apt-get update -qq 2>&1');
                        
                        // Try installing snort (available in Ubuntu universe repo)
                        $result = Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y snort 2>&1');
                        
                        if (!$result->successful()) {
                            // Try snort3 (newer package name on some distros)
                            $result = Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y snort3 2>&1');
                        }
                        
                        if (!$result->successful()) {
                            // Try adding Snort PPA (Ubuntu only)
                            if (in_array($distro, ['ubuntu', 'linuxmint', 'pop'])) {
                                Log::info('Trying Snort via PPA...');
                                Process::timeout(60)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common 2>&1');
                                Process::timeout(60)->run('add-apt-repository -y ppa:oisf/suricata-stable 2>&1');
                                Process::run('apt-get update -qq 2>&1');
                                $result = Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y snort 2>&1');
                                if (!$result->successful()) {
                                    $result = Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y snort3 2>&1');
                                }
                            }
                        }
                        
                        if (!$result->successful()) {
                            // Compile from source as last resort
                            Log::info('Trying Snort 3 compile from source...');
                            $result = $this->compileSnort3FromSource();
                        }
                    } elseif (in_array($distro, ['rhel', 'centos', 'rocky', 'almalinux', 'ol'])) {
                        Process::run('yum install -y epel-release 2>&1');
                        $result = Process::timeout(600)->run('yum install -y snort 2>&1');
                    } elseif ($distro === 'fedora') {
                        $result = Process::timeout(600)->run('dnf install -y snort 2>&1');
                    } elseif ($distro === 'arch' || $distro === 'manjaro') {
                        $result = Process::timeout(600)->run('pacman -S --noconfirm snort 2>&1');
                    } else {
                        // Try apt first (most common), then yum
                        $aptCheck = Process::run('which apt-get 2>&1');
                        if ($aptCheck->successful()) {
                            $this->preseedSnortDebconf();
                            Process::run('apt-get update -qq 2>&1');
                            $result = Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y snort 2>&1');
                        } else {
                            $yumCheck = Process::run('which yum 2>&1');
                            if ($yumCheck->successful()) {
                                $result = Process::timeout(600)->run('yum install -y snort 2>&1');
                            }
                        }
                    }

                    // Fallback: try snap
                    if (empty($result) || !$result->successful()) {
                        $snapCheck = Process::run('which snap 2>&1');
                        if ($snapCheck->successful()) {
                            $result = Process::timeout(600)->run('snap install snort 2>&1');
                        }
                    }

                    if (empty($result) || !$result->successful()) {
                        return ['success' => false, 'error' => "Linux Snort install failed (distro: {$distro}). " . ($result ? $result->output() : 'No package manager found')];
                    }
                    break;

                case 'windows':
                    // Step 1: Ensure Npcap is installed (required for Snort to capture packets)
                    $this->ensureNpcapInstalled();

                    // Check if Snort is already installed
                    $snortCheck = Process::run('where snort 2>&1');
                    if ($snortCheck->successful()) {
                        Log::info('Snort already installed on Windows');
                        break;
                    }
                    // Also check common install paths
                    $commonPaths = ['C:\\Snort\\bin\\snort.exe', 'C:\\Program Files\\Snort\\bin\\snort.exe'];
                    foreach ($commonPaths as $sp) {
                        if (file_exists($sp)) {
                            Log::info("Snort found at {$sp}");
                            break 2;
                        }
                    }

                    $snortInstalled = false;
                    $errors = [];

                    // Method 1: Try Chocolatey (check default path since SYSTEM PATH may not include it)
                    $chocoPath = 'C:\\ProgramData\\chocolatey\\bin\\choco.exe';
                    $chocoAvailable = file_exists($chocoPath);
                    if (!$chocoAvailable) {
                        $chocoCheck = Process::run('where choco 2>&1');
                        $chocoAvailable = $chocoCheck->successful();
                        if ($chocoAvailable) {
                            $chocoPath = 'choco';
                        }
                    }

                    if ($chocoAvailable) {
                        Log::info('Trying Snort install via Chocolatey...');
                        $r = Process::timeout(600)->run("\"{$chocoPath}\" install snort -y 2>&1");
                        if ($r->successful()) {
                            $snortInstalled = true;
                        } else {
                            $errors[] = 'Chocolatey: ' . substr($r->output() ?: $r->errorOutput(), 0, 200);
                        }
                    } else {
                        $errors[] = 'Chocolatey: not installed';
                    }

                    // Method 2: Try WinGet (check default paths)
                    if (!$snortInstalled) {
                        $wingetPath = null;
                        $wingetPaths = [
                            'C:\\Users\\' . get_current_user() . '\\AppData\\Local\\Microsoft\\WindowsApps\\winget.exe',
                            'C:\\Program Files\\WindowsApps\\Microsoft.DesktopAppInstaller_*\\winget.exe',
                        ];
                        foreach ($wingetPaths as $wp) {
                            $found = glob($wp);
                            if (!empty($found)) {
                                $wingetPath = $found[0];
                                break;
                            }
                        }
                        if (!$wingetPath) {
                            $wingetCheck = Process::run('where winget 2>&1');
                            if ($wingetCheck->successful()) {
                                $wingetPath = 'winget';
                            }
                        }

                        if ($wingetPath) {
                            Log::info('Trying Snort install via WinGet...');
                            $r = Process::timeout(600)->run("\"{$wingetPath}\" install Snort.Snort --accept-package-agreements --accept-source-agreements 2>&1");
                            if ($r->successful()) {
                                $snortInstalled = true;
                            } else {
                                $errors[] = 'WinGet: ' . substr($r->output() ?: $r->errorOutput(), 0, 200);
                            }
                        } else {
                            $errors[] = 'WinGet: not installed';
                        }
                    }

                    // Method 3: Download Snort 2.9.x MSI from snort.org (Snort 3 has no Windows installer)
                    if (!$snortInstalled) {
                        Log::info('Trying Snort 2.9 install via direct MSI download...');
                        $scriptContent = "\$ErrorActionPreference = 'Stop'\r\n" .
                            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\r\n" .
                            "try {\r\n" .
                            "    \$snortMsi = \"Snort_2_9_20_Installer.x64.msi\"\r\n" .
                            "    \$url = \"https://www.snort.org/downloads/snort/\$snortMsi\"\r\n" .
                            "    \$outPath = \"\$env:TEMP\\\\\$snortMsi\"\r\n" .
                            "    Write-Output \"Downloading from \$url...\"\r\n" .
                            "    \$wc = New-Object System.Net.WebClient\r\n" .
                            "    \$wc.Headers.Add('User-Agent', 'SecurityOneIDS')\r\n" .
                            "    \$wc.DownloadFile(\$url, \$outPath)\r\n" .
                            "    if (Test-Path \$outPath) {\r\n" .
                            "        Write-Output 'Installing Snort MSI...'\r\n" .
                            "        Start-Process msiexec.exe -ArgumentList '/i', \$outPath, '/quiet', '/norestart', 'INSTALLDIR=C:\\Snort' -Wait -NoNewWindow\r\n" .
                            "        Remove-Item \$outPath -Force -ErrorAction SilentlyContinue\r\n" .
                            "        # Create necessary directories\r\n" .
                            "        New-Item -ItemType Directory -Path 'C:\\Snort\\rules' -Force | Out-Null\r\n" .
                            "        New-Item -ItemType Directory -Path 'C:\\Snort\\log' -Force | Out-Null\r\n" .
                            "        New-Item -ItemType Directory -Path 'C:\\Snort\\etc' -Force | Out-Null\r\n" .
                            "        # Generate default snort.conf if missing\r\n" .
                            "        if (-not (Test-Path 'C:\\Snort\\etc\\snort.conf')) {\r\n" .
                            "            @'\r\n" .
                            "var HOME_NET any\r\n" .
                            "var EXTERNAL_NET any\r\n" .
                            "var RULE_PATH C:\\Snort\\rules\r\n" .
                            "config logdir: C:\\Snort\\log\r\n" .
                            "config detection: search-method ac-full\r\n" .
                            "output alert_fast: snort.alert.fast\r\n" .
                            "include \$RULE_PATH\\local.rules\r\n" .
                            "'@ | Set-Content 'C:\\Snort\\etc\\snort.conf' -Encoding UTF8\r\n" .
                            "        }\r\n" .
                            "        if (-not (Test-Path 'C:\\Snort\\rules\\local.rules')) {\r\n" .
                            "            '# Security One IDS - Local Rules' | Set-Content 'C:\\Snort\\rules\\local.rules' -Encoding UTF8\r\n" .
                            "        }\r\n" .
                            "        if (Test-Path 'C:\\Snort\\bin\\snort.exe') {\r\n" .
                            "            Write-Output 'INSTALL_OK'\r\n" .
                            "        } else {\r\n" .
                            "            Write-Output 'MSI_INSTALLED_BUT_EXE_NOT_FOUND'\r\n" .
                            "        }\r\n" .
                            "    } else {\r\n" .
                            "        Write-Output 'DOWNLOAD_FAILED: file not created'\r\n" .
                            "    }\r\n" .
                            "} catch {\r\n" .
                            "    Write-Output \"DOWNLOAD_FAILED: \$_\"\r\n" .
                            "}\r\n";

                        $scriptPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'snort_install_' . uniqid() . '.ps1';
                        file_put_contents($scriptPath, $scriptContent);

                        $r = Process::timeout(600)->run("powershell -NoProfile -ExecutionPolicy Bypass -File \"{$scriptPath}\" 2>&1");
                        $output = $r->output();
                        @unlink($scriptPath);

                        if (str_contains($output, 'INSTALL_OK')) {
                            $snortInstalled = true;
                        } else {
                            $errors[] = 'Direct MSI: ' . substr($output ?: $r->errorOutput() ?: 'no output', 0, 200);
                        }
                    }

                    if (!$snortInstalled) {
                        // Create Snort directories as fallback for manual install
                        Process::run('mkdir C:\\Snort\\rules 2>&1');
                        Process::run('mkdir C:\\Snort\\log 2>&1');
                        Process::run('mkdir C:\\Snort\\etc 2>&1');
                        return ['success' => false, 'error' => 'Windows Snort auto-install failed. ' . implode(' | ', $errors)];
                    }
                    break;

                default:
                    return ['success' => false, 'error' => "Unsupported platform: {$platform}"];
            }

            // Create default directories
            if ($platform !== 'windows') {
                Process::run('mkdir -p /var/log/snort /etc/snort/rules 2>/dev/null');
            }

            // Download community rules
            $snort = new \App\Services\Detection\SnortEngine();
            if ($snort->isInstalled()) {
                $snort->updateRules();
                return ['success' => true, 'version' => $snort->getVersion()];
            }

            return ['success' => false, 'error' => 'Snort installed but binary not found'];

        } catch (\Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Ensure Npcap is installed on Windows (required for Snort packet capture)
     */
    private function ensureNpcapInstalled(): void
    {
        if (PHP_OS_FAMILY !== 'Windows') {
            return;
        }

        // Clean up stale cache files from previous code versions
        @unlink(storage_path('app/npcap_installed.txt'));
        @unlink(storage_path('app/pcap_verified.txt'));
        @unlink(storage_path('app/pcap_cooldown.txt'));
        @unlink(storage_path('app/pcap_attempt.txt'));

        $cacheFile = storage_path('app/pcap_ok_v3.txt');
        if (file_exists($cacheFile)) {
            return;
        }

        $snortPath = 'C:\\Snort\\bin\\snort.exe';
        if (!file_exists($snortPath)) {
            return;
        }

        // Check if driver already works
        if ($this->snortCanSeeInterfaces($snortPath)) {
            file_put_contents($cacheFile, date('c'));
            return;
        }

        // Try starting NPF or Npcap service (driver may be installed but service not running)
        try {
            Process::timeout(10)->run('net start npcap 2>&1');
            Process::timeout(10)->run('net start npf 2>&1');
            sleep(2);
            if ($this->snortCanSeeInterfaces($snortPath)) {
                file_put_contents($cacheFile, date('c'));
                Log::info('[Pcap] Packet capture service started, interfaces now visible');
                $this->reportAgentEvent('snort_install', 'Packet capture activated');
                return;
            }
        } catch (\Exception $e) {
            // Services do not exist
        }

        // Rate-limit install (once per 10 minutes for faster retries on failure)
        $attemptFile = storage_path('app/npcap_attempt_v2.txt');
        if (file_exists($attemptFile) && (time() - filemtime($attemptFile)) < 600) {
            return;
        }
        file_put_contents($attemptFile, date('c'));

        Log::info('[Pcap] Installing/configuring Npcap for Windows...');

        try {
            $script = "\$ErrorActionPreference='SilentlyContinue'\r\n" .
                "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12\r\n" .
                "\r\n" .
                "# Step 0: Diagnostic — check current state\r\n" .
                "Write-Output 'DIAG_START'\r\n" .
                "Write-Output \"Npcap dir exists: \$(Test-Path 'C:\\Windows\\System32\\Npcap')\"\r\n" .
                "Write-Output \"wpcap System32: \$(Test-Path 'C:\\Windows\\System32\\wpcap.dll')\"\r\n" .
                "Write-Output \"wpcap Npcap: \$(Test-Path 'C:\\Windows\\System32\\Npcap\\wpcap.dll')\"\r\n" .
                "Write-Output \"Packet System32: \$(Test-Path 'C:\\Windows\\System32\\Packet.dll')\"\r\n" .
                "Write-Output \"Packet Npcap: \$(Test-Path 'C:\\Windows\\System32\\Npcap\\Packet.dll')\"\r\n" .
                "Write-Output \"wpcap Snort: \$(Test-Path 'C:\\Snort\\bin\\wpcap.dll')\"\r\n" .
                "sc.exe query npcap 2>&1|Select-String 'STATE'|Write-Output\r\n" .
                "sc.exe query npf 2>&1|Select-String 'STATE'|Write-Output\r\n" .
                "\r\n" .
                "# Step 1: Try starting npcap service (driver may already be installed)\r\n" .
                "net start npcap 2>&1|Write-Output\r\n" .
                "net start npf 2>&1|Write-Output\r\n" .
                "Start-Sleep 2\r\n" .
                "\r\n" .
                "# Step 2: If Npcap DLLs exist in System32\\Npcap, copy to Snort\\bin and System32\r\n" .
                "\$npcapDir='C:\\Windows\\System32\\Npcap'\r\n" .
                "if(Test-Path \"\$npcapDir\\wpcap.dll\"){\r\n" .
                "  Write-Output 'Found Npcap DLLs, copying to Snort and System32...'\r\n" .
                "  Copy-Item \"\$npcapDir\\wpcap.dll\" 'C:\\Windows\\System32\\wpcap.dll' -Force -EA SilentlyContinue\r\n" .
                "  Copy-Item \"\$npcapDir\\Packet.dll\" 'C:\\Windows\\System32\\Packet.dll' -Force -EA SilentlyContinue\r\n" .
                "  Copy-Item \"\$npcapDir\\wpcap.dll\" 'C:\\Snort\\bin\\wpcap.dll' -Force -EA SilentlyContinue\r\n" .
                "  Copy-Item \"\$npcapDir\\Packet.dll\" 'C:\\Snort\\bin\\Packet.dll' -Force -EA SilentlyContinue\r\n" .
                "  # Add Npcap dir to system PATH if not already there\r\n" .
                "  \$sysPath=[System.Environment]::GetEnvironmentVariable('Path','Machine')\r\n" .
                "  if(\$sysPath -notlike \"*Npcap*\"){\r\n" .
                "    [System.Environment]::SetEnvironmentVariable('Path',\$sysPath+';'+\$npcapDir,'Machine')\r\n" .
                "    \$env:Path=\$env:Path+';'+\$npcapDir\r\n" .
                "    Write-Output 'Added Npcap to system PATH'\r\n" .
                "  }\r\n" .
                "}\r\n" .
                "\r\n" .
                "# Step 3: Verify after DLL copy\r\n" .
                "\$w=&'C:\\Snort\\bin\\snort.exe' -W 2>&1|Out-String\r\n" .
                "Write-Output \"SNORT_W:\$w\"\r\n" .
                "if(\$w -match '\\d+\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+\\.\\d+'){Write-Output 'PCAP_OK'; exit 0}\r\n" .
                "\r\n" .
                "# Step 4: If DLLs don't exist, try full install via Npcap /S\r\n" .
                "Write-Output 'STRATEGY:npcap_silent'\r\n" .
                "\$npcapExe=\"\$env:TEMP\\npcap-1.87.exe\"\r\n" .
                "if(-not(Test-Path \$npcapExe)){\r\n" .
                "  Write-Output 'Downloading Npcap 1.87...'\r\n" .
                "  (New-Object Net.WebClient).DownloadFile('https://npcap.com/dist/npcap-1.87.exe',\$npcapExe)\r\n" .
                "}\r\n" .
                "\$p=Start-Process \$npcapExe -ArgumentList '/S','/winpcap_mode=yes','/loopback_support=yes','/npf_startup=yes' -Wait -PassThru\r\n" .
                "Write-Output \"EXIT:\$(\$p.ExitCode)\"\r\n" .
                "Start-Sleep 5\r\n" .
                "net start npcap 2>&1|Write-Output\r\n" .
                "net start npf 2>&1|Write-Output\r\n" .
                "\r\n" .
                "# Copy DLLs again after install attempt\r\n" .
                "if(Test-Path \"\$npcapDir\\wpcap.dll\"){\r\n" .
                "  Copy-Item \"\$npcapDir\\wpcap.dll\" 'C:\\Windows\\System32\\wpcap.dll' -Force -EA SilentlyContinue\r\n" .
                "  Copy-Item \"\$npcapDir\\Packet.dll\" 'C:\\Windows\\System32\\Packet.dll' -Force -EA SilentlyContinue\r\n" .
                "  Copy-Item \"\$npcapDir\\wpcap.dll\" 'C:\\Snort\\bin\\wpcap.dll' -Force -EA SilentlyContinue\r\n" .
                "  Copy-Item \"\$npcapDir\\Packet.dll\" 'C:\\Snort\\bin\\Packet.dll' -Force -EA SilentlyContinue\r\n" .
                "}\r\n" .
                "\r\n" .
                "\$w=&'C:\\Snort\\bin\\snort.exe' -W 2>&1|Out-String\r\n" .
                "Write-Output \"SNORT_W:\$w\"\r\n" .
                "if(\$w -match '\\d+\\s+\\S+\\s+\\d+\\.\\d+\\.\\d+\\.\\d+'){Write-Output 'PCAP_OK'}else{Write-Output 'PCAP_FAIL'}\r\n";

            // Use a fixed path under Snort directory (avoids AV flagging random scripts in temp)
            $scriptDir = 'C:\\Snort\\scripts';
            if (!is_dir($scriptDir)) {
                @mkdir($scriptDir, 0755, true);
            }
            $path = $scriptDir . DIRECTORY_SEPARATOR . 'npcap_setup.ps1';
            file_put_contents($path, $script);
            $r = Process::timeout(300)->run("powershell -NoProfile -ExecutionPolicy Bypass -File \"{$path}\" 2>&1");
            $out = $r->output();
            // Don't delete — keep for diagnostics and AV whitelisting

            Log::info('[Pcap] Output: ' . substr($out, 0, 2000));

            if (str_contains($out, 'PCAP_OK')) {
                file_put_contents($cacheFile, date('c'));
                @unlink($attemptFile);
                Log::info('[Pcap] Npcap installed and verified');
                $this->reportAgentEvent('snort_install', 'Npcap installed successfully');
            } else {
                $strategy = 'unknown';
                if (preg_match('/STRATEGY:(\w+)/', $out, $m)) {
                    $strategy = $m[1];
                }
                Log::warning('[Pcap] Npcap automatic install failed — manual installation required', [
                    'strategy' => $strategy,
                    'output' => substr($out, 0, 1000),
                ]);
                // Cache failure for 24 hours — Npcap free edition cannot be silently installed,
                // no point retrying every 10 minutes. User must install manually.
                file_put_contents($attemptFile, 'manual_required:' . date('c'));
                // Set a long cooldown by backdating the mtime check
                touch($attemptFile, time());
                $this->reportAgentEvent('snort_error', 'Npcap 無法自動安裝，請手動從 https://npcap.com 下載安裝後重啟系統');
            }
        } catch (\Exception $e) {
            Log::error('[Pcap] Error: ' . $e->getMessage());
        }
    }

    /**
     * Check if Snort can see network interfaces (packet capture driver working)
     */
    private function snortCanSeeInterfaces(string $snortPath): bool
    {
        try {
            $r = Process::timeout(10)->run("\"{$snortPath}\" -W 2>&1");
            return (bool) preg_match('/\d+\s+\S+\s+\d+\.\d+\.\d+\.\d+/', $r->output());
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Compile Snort 3 from source (Ubuntu/Debian fallback)
     */
    private function compileSnort3FromSource(): \Illuminate\Process\ProcessResult
    {
        // Install build dependencies
        $deps = 'build-essential cmake libhwloc-dev libluajit-5.1-dev libssl-dev libpcap-dev ' .
                'libpcre2-dev pkg-config zlib1g-dev libdaq-dev flex bison';
        Process::timeout(300)->run("apt-get install -y {$deps} 2>&1");

        $buildDir = '/tmp/snort3-build-' . uniqid();
        @mkdir($buildDir, 0755, true);

        // Download latest Snort 3 source
        $downloadResult = Process::timeout(120)->run(
            "cd {$buildDir} && " .
            "curl -fsSL https://api.github.com/repos/snort3/snort3/releases/latest " .
            "| grep 'tarball_url' | cut -d'\"' -f4 " .
            "| xargs curl -fsSL -o snort3.tar.gz 2>&1"
        );

        if (!$downloadResult->successful()) {
            // Fallback: try direct download
            Process::timeout(120)->run(
                "cd {$buildDir} && curl -fsSL -o snort3.tar.gz " .
                "https://github.com/snort3/snort3/archive/refs/heads/master.tar.gz 2>&1"
            );
        }

        // Extract, build, install
        $result = Process::timeout(900)->run(
            "cd {$buildDir} && " .
            "tar xzf snort3.tar.gz --strip-components=1 && " .
            "mkdir -p build && cd build && " .
            "cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local 2>&1 && " .
            "make -j\$(nproc) 2>&1 && " .
            "make install 2>&1 && " .
            "ldconfig 2>&1"
        );

        // Cleanup
        Process::run("rm -rf {$buildDir} 2>/dev/null");

        return $result;
    }

    /**
     * Pre-seed debconf answers for Snort package to avoid interactive prompts
     */
    private function preseedSnortDebconf(): void
    {
        try {
            // Detect default network interface
            $interface = 'any';
            $ifResult = Process::run("ip route show default 2>/dev/null | awk '{print \$5}' | head -1");
            $detected = trim($ifResult->output());
            if (!empty($detected)) {
                $interface = $detected;
            }

            // Pre-seed answers for debconf prompts
            $selections = [
                "snort snort/interface string {$interface}",
                'snort snort/address_range string 0.0.0.0/0',
                'snort snort/startup string boot',
                'snort snort/invalid_interface note',
            ];

            foreach ($selections as $selection) {
                Process::run("echo '{$selection}' | debconf-set-selections 2>&1");
            }

            Log::debug('Snort debconf pre-seeded', ['interface' => $interface]);
        } catch (\Exception $e) {
            Log::debug('Failed to pre-seed Snort debconf: ' . $e->getMessage());
        }
    }

    /**
     * Sync Snort rules from Hub if hash differs
     */
    private function syncSnortRules(string $hubHash, string $mode = 'ids'): void
    {
        try {
            // After a code update, PHP still has old classes in memory.
            // Skip rule sync this cycle — next execution will use fresh code.
            if ($this->codeUpdated) {
                Log::info('Skipping rule sync — code was just updated, will sync with fresh code next cycle');
                return;
            }

            $snort = app(\App\Services\Detection\SnortEngine::class);
            if (!$snort->isInstalled()) {
                return;
            }

            // Compare local rules hash with Hub hash
            $localHash = $this->getLocalSnortRulesHash();
            if ($localHash === $hubHash) {
                Log::debug('Snort rules hash matches Hub, no sync needed');
                return;
            }

            Log::info('Snort rules hash mismatch, syncing from Hub...', [
                'local_hash' => $localHash,
                'hub_hash' => $hubHash,
            ]);

            // Fetch rules from Hub
            if (empty($this->wafUrl) || empty($this->agentToken)) {
                Log::warning('Cannot sync Snort rules: Hub URL or token not configured');
                return;
            }

            // Determine Snort version to request version-specific rules from Hub
            $snortVersion = $snort->isSnort2() ? '2' : '3';

            $response = \Illuminate\Support\Facades\Http::timeout(120)
                ->withHeaders(['Authorization' => "Bearer {$this->agentToken}"])
                ->get("{$this->wafUrl}/api/ids/agents/snort-rules", [
                    'token' => $this->agentToken,
                    'snort_version' => $snortVersion,
                ]);

            if (!$response->successful()) {
                Log::error('Failed to fetch Snort rules from Hub', ['status' => $response->status()]);
                $this->reportAgentEvent('error', 'Snort 規則同步失敗：無法從 Hub 下載', [
                    'http_status' => $response->status(),
                ]);
                return;
            }

            $data = $response->json();

            // Support both new format (rules_text) and legacy format (rules array)
            $rulesContent = '';
            $ruleCount = 0;

            if (!empty($data['rules_text'])) {
                // New optimized format: pre-joined rule text
                $rulesContent = $data['rules_text'] . "\n";
                $ruleCount = $data['rules_count'] ?? substr_count($rulesContent, "\n");
            } elseif (!empty($data['rules'])) {
                // Legacy format: array of rule objects
                foreach ($data['rules'] as $rule) {
                    $rulesContent .= ($rule['rule_content'] ?? '') . "\n";
                }
                $ruleCount = count($data['rules']);
            } else {
                Log::info('No Snort rules received from Hub');
                return;
            }

            $rulesPath = $snort->getDetectedRulesDir() . '/hub_custom.rules';

            // Convert/validate rules for platform compatibility
            if (!$snort->isSnort2()) {
                $conversion = $snort->convertRulesForSnort3($rulesContent);
                $rulesContent = $conversion['content'];
                $ruleCount = $conversion['stats']['kept_as_is'] + $conversion['stats']['converted'];
            } else {
                // Snort 2: validate rules to catch syntax issues that would crash startup
                $validation = $snort->validateRulesForSnort2($rulesContent);
                $rulesContent = $validation['content'];
                $ruleCount = $validation['stats']['kept'];
            }

            // IPS mode: convert alert → drop to actually block traffic
            // - Snort 3 (any Unix): supports inline via DAQ (AFPacket on Linux, pcap with NFQ on macOS)
            // - Snort 2 on Linux: supports inline via -Q with afpacket DAQ
            // - Snort 2 on Windows/macOS: passive-only (WinPcap/pcap DAQ) — drop rules
            //   are silently ignored, producing 0 alerts. Keep as alert for visibility.
            $canInline = !$snort->isSnort2() || PHP_OS_FAMILY === 'Linux';
            if ($mode === 'ips' && $canInline) {
                $rulesContent = $snort->applyIpsMode($rulesContent);
            } elseif ($mode === 'ips') {
                Log::info('IPS mode: skipping alert→drop conversion (Snort 2 on ' . PHP_OS_FAMILY . ' lacks inline DAQ, rules stay as alert)');
            }

            // For Snort 2: prepend variable/ClassType definitions that may be missing
            // from the Windows snort.conf. Without these, rules referencing undefined
            // variables or ClassTypes cause fatal errors at startup.
            if ($snort->isSnort2()) {
                $rulesHeader = $this->buildSnort2RulesHeader($rulesContent);
                $rulesContent = $rulesHeader . $rulesContent;
            }

            file_put_contents($rulesPath, $rulesContent);

            // Store the new hash locally (prevents re-download every cycle)
            $hashPath = storage_path('app/snort_rules_hash.txt');
            file_put_contents($hashPath, $data['rules_hash'] ?? $hubHash);

            // Always stop and restart with retry to handle rule errors
            // reload() on Windows does stop+start() (no retry), which crashes on bad rules
            if ($snort->isRunning()) {
                $snort->stop();
            }
            $startResult = $snort->startWithRetry($mode);
            if (!$startResult['success']) {
                Log::warning('Snort failed to start after rule sync', ['error' => $startResult['error'] ?? 'unknown']);
            }

            Log::info("Synced {$ruleCount} Snort rules from Hub");

            $this->reportAgentEvent('snort_rule_sync', "已從 Hub 同步 {$ruleCount} 條 Snort 規則", [
                'rule_count' => $ruleCount,
                'rules_hash' => $data['rules_hash'] ?? $hubHash,
            ]);

        } catch (\Exception $e) {
            Log::error('Snort rules sync failed: ' . $e->getMessage());
            $this->reportAgentEvent('error', 'Snort 規則同步例外：' . $e->getMessage());
        }
    }

    /**
     * Build a header with variable and ClassType definitions for Snort 2 rules.
     * Scans the rules content for referenced variables and ClassTypes, then
     * generates definitions for any that may be missing from the base config.
     */
    private function buildSnort2RulesHeader(string $rulesContent): string
    {
        $header = "# Auto-generated Snort 2 compatibility definitions\n";
        $added = false;

        // Common variables that may not be defined in a basic Windows snort.conf
        // Default them to $HOME_NET (safest fallback)
        $optionalVars = [
            'DNS_SERVERS', 'SMTP_SERVERS', 'SQL_SERVERS', 'TELNET_SERVERS',
            'SSH_SERVERS', 'FTP_SERVERS', 'SIP_SERVERS', 'SNMP_SERVERS',
        ];
        foreach ($optionalVars as $var) {
            if (preg_match('/\$' . $var . '\b/', $rulesContent)) {
                $header .= "var {$var} \$HOME_NET\n";
                $added = true;
            }
        }

        // Port variables that may be missing
        $optionalPorts = [
            'SHELLCODE_PORTS' => '!80',
            'FILE_DATA_PORTS' => '[$HTTP_PORTS,110,143]',
            'GTP_PORTS' => '2152',
            'SSH_PORTS' => '22',
        ];
        foreach ($optionalPorts as $var => $default) {
            if (preg_match('/\$' . $var . '\b/', $rulesContent)) {
                $header .= "portvar {$var} {$default}\n";
                $added = true;
            }
        }

        // Find all ClassTypes used in rules and define any non-standard ones
        $standardClassTypes = [
            'attempted-admin', 'attempted-user', 'inappropriate-content',
            'policy-violation', 'shellcode-detect', 'successful-admin',
            'successful-user', 'trojan-activity', 'unsuccessful-user',
            'web-application-attack', 'attempted-dos', 'attempted-recon',
            'bad-unknown', 'default-login-attempt', 'denial-of-service',
            'misc-attack', 'non-standard-protocol', 'rpc-portmap-decode',
            'successful-dos', 'successful-recon-largescale', 'successful-recon-limited',
            'suspicious-filename-detect', 'suspicious-login', 'system-call-detect',
            'unusual-client-port-connection', 'web-application-activity',
            'icmp-event', 'misc-activity', 'network-scan', 'not-suspicious',
            'protocol-command-decode', 'string-detect', 'unknown',
            'tcp-connection', 'pup-activity',
        ];

        if (preg_match_all('/classtype\s*:\s*([a-zA-Z0-9_-]+)\s*;/', $rulesContent, $matches)) {
            $usedTypes = array_unique($matches[1]);
            foreach ($usedTypes as $ct) {
                if (!in_array(strtolower($ct), $standardClassTypes, true)) {
                    // Define as priority 1 (lowest severity) — safe default
                    $header .= "config classification: {$ct},{$ct},1\n";
                    $added = true;
                }
            }
        }

        if ($added) {
            $header .= "\n";
            return $header;
        }

        return '';
    }


    /**
     * Collect new Snort alerts and send them to Hub
     */
    private function collectSnortAlerts(): void
    {
        try {
            $snort = app(\App\Services\Detection\SnortEngine::class);
            if (!$snort->isInstalled()) {
                return;
            }

            // Determine alert log path
            $alertLogPath = $snort->getAlertLogPath();
            if (!$alertLogPath || !file_exists($alertLogPath)) {
                Log::debug('Snort alert log not found', ['path' => $alertLogPath]);
                return;
            }

            // Fix permissions if file exists but is not readable (Snort runs as root)
            if (!is_readable($alertLogPath) && PHP_OS_FAMILY !== 'Windows') {
                $logDir = dirname($alertLogPath);
                Process::run("sudo chmod -R o+rX {$logDir} 2>/dev/null");
                clearstatcache(true, $alertLogPath);
                if (!is_readable($alertLogPath)) {
                    Log::warning('Snort alert log exists but is not readable', ['path' => $alertLogPath]);
                    return;
                }
            }

            // Track file position to avoid resending alerts
            $positionFile = storage_path('app/snort_alert_position.txt');
            $lastPosition = 0;
            if (file_exists($positionFile)) {
                $lastPosition = (int) file_get_contents($positionFile);
            }

            $fileSize = filesize($alertLogPath);

            // File was rotated or truncated — reset position
            if ($fileSize < $lastPosition) {
                $lastPosition = 0;
            }

            // No new data
            if ($fileSize <= $lastPosition) {
                return;
            }

            // Read new lines from the alert log
            $handle = fopen($alertLogPath, 'r');
            if (!$handle) {
                return;
            }

            fseek($handle, $lastPosition);
            $newAlerts = [];
            $maxAlerts = 50; // Rate limit per sync cycle

            while (!feof($handle) && count($newAlerts) < $maxAlerts) {
                $line = fgets($handle);
                if ($line === false) {
                    break;
                }

                $line = trim($line);
                if (empty($line)) {
                    continue;
                }

                // Try Snort 2.9 alert.fast text format first:
                // 02/07-06:37:14.011770  [**] [1:527:8] BAD-TRAFFIC same SRC/DST [**] [Classification: ...] [Priority: 2] {UDP} 0.0.0.0:68 -> 255.255.255.255:67
                if (preg_match('/^\d{2}\/\d{2}-[\d:.]+\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]/', $line, $m)) {
                    $sid = $m[1];
                    $msg = $m[2];

                    $classification = 'snort-detection';
                    if (preg_match('/\[Classification:\s*(.+?)\]/', $line, $cm)) {
                        $classification = $cm[1];
                    }

                    $priority = 3;
                    if (preg_match('/\[Priority:\s*(\d+)\]/', $line, $pm)) {
                        $priority = (int) $pm[1];
                    }

                    $proto = 'unknown';
                    if (preg_match('/\{(\w+)\}/', $line, $protom)) {
                        $proto = $protom[1];
                    }

                    $sourceIp = null;
                    $sourcePort = null;
                    $destIp = null;
                    $destPort = null;
                    if (preg_match('/\}\s+([\d.]+):?(\d+)?\s*->\s*([\d.]+):?(\d+)?/', $line, $ipm)) {
                        $sourceIp = $ipm[1];
                        $sourcePort = !empty($ipm[2]) ? $ipm[2] : null;
                        $destIp = $ipm[3];
                        $destPort = !empty($ipm[4]) ? $ipm[4] : null;
                    }

                    if (!$sourceIp || !filter_var($sourceIp, FILTER_VALIDATE_IP)) {
                        continue;
                    }

                    $severity = match (true) {
                        $priority <= 1 => 'critical',
                        $priority <= 2 => 'high',
                        $priority <= 3 => 'medium',
                        default => 'low',
                    };

                    $newAlerts[] = [
                        'source_ip' => $sourceIp,
                        'severity' => $severity,
                        'category' => $classification,
                        'source' => 'snort',
                        'detections' => "[SNORT] SID:{$sid} {$msg} (Priority: {$priority})",
                        'raw_log' => $line,
                        'uri' => $destIp ? "{$destIp}:{$destPort}" : null,
                        'method' => strtoupper($proto),
                    ];
                    continue;
                }

                // Try JSON (Snort 3 alert_json.txt)
                $decoded = json_decode($line, true);
                if (!$decoded) {
                    continue;
                }

            // Map Snort alert fields to Hub format
                $sourceIp = $decoded['src_addr'] ?? null;
                if (!$sourceIp) {
                    // Try alternate field names — src_ap is "ip:port" format
                    $srcAp = $decoded['src_ap'] ?? null;
                    if ($srcAp) {
                        // Handle IPv6 (e.g. "fe80::ce4:81e4:e3b9:8916:0") and IPv4 ("1.2.3.4:80")
                        // Port is always the last ":number" segment
                        $sourceIp = preg_replace('/:\d+$/', '', $srcAp);
                    }
                }

                // Accept both IPv4 and IPv6
                if (!$sourceIp || (!filter_var($sourceIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && !filter_var($sourceIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))) {
                    // Still try to process — use raw src_ap if available
                    $sourceIp = $sourceIp ?: ($decoded['src_ap'] ?? 'unknown');
                }

                $priority = (int) ($decoded['priority'] ?? 3);
                $severity = match (true) {
                    $priority <= 1 => 'critical',
                    $priority <= 2 => 'high',
                    $priority <= 3 => 'medium',
                    default => 'low',
                };

                $msg = $decoded['msg'] ?? $decoded['rule'] ?? 'Snort Alert';
                $classification = $decoded['class'] ?? $decoded['classtype'] ?? 'snort-detection';
                $sid = $decoded['sid'] ?? $decoded['gid'] ?? null;
                $action = $decoded['action'] ?? 'alert';
                $proto = $decoded['proto'] ?? $decoded['protocol'] ?? 'unknown';
                $destIp = $decoded['dst_addr'] ?? null;
                $destPort = $decoded['dst_port'] ?? null;
                if (!$destIp) {
                    $dstAp = $decoded['dst_ap'] ?? null;
                    if ($dstAp) {
                        // Extract port (last :number) and IP
                        if (preg_match('/:(\d+)$/', $dstAp, $portMatch)) {
                            $destPort = $destPort ?? $portMatch[1];
                        }
                        $destIp = preg_replace('/:\d+$/', '', $dstAp);
                    }
                }

                $newAlerts[] = [
                    'source_ip' => $sourceIp,
                    'severity' => $severity,
                    'category' => $classification,
                    'source' => 'snort',
                    'detections' => "[SNORT] SID:{$sid} {$msg} (Action: {$action}, Priority: {$priority})",
                    'raw_log' => "{$proto} {$sourceIp} -> {$destIp}:{$destPort} | {$msg}",
                    'uri' => $destIp ? "{$destIp}:{$destPort}" : null,
                    'method' => strtoupper($proto),
                ];
            }

            // Save position
            $newPosition = ftell($handle);
            fclose($handle);
            file_put_contents($positionFile, $newPosition);

            if (empty($newAlerts)) {
                return;
            }

            // Send alerts to Hub
            $sent = 0;
            foreach ($newAlerts as $alertData) {
                try {
                    $this->syncAlert($alertData);
                    $sent++;
                } catch (\Exception $e) {
                    Log::warning('Failed to send Snort alert: ' . $e->getMessage());
                }
            }

            if ($sent > 0) {
                Log::info("Sent {$sent} Snort alerts to Hub");
                $this->reportAgentEvent('snort_alert', "已上報 {$sent} 條 Snort 告警至 Hub");
            }

        } catch (\Exception $e) {
            Log::error('Snort alert collection failed: ' . $e->getMessage());
        }
    }

    /**
     * Get local Snort rules hash
     */
    private function getLocalSnortRulesHash(): string
    {
        $hashPath = storage_path('app/snort_rules_hash.txt');
        if (file_exists($hashPath)) {
            return trim(file_get_contents($hashPath));
        }
        return '';
    }

    /**
     * Upload local Snort rules from Agent to Hub
     */
    public function uploadSnortRulesToHub(): void
    {
        try {
            if (empty($this->wafUrl) || empty($this->agentToken)) {
                return;
            }

            $snort = app(\App\Services\Detection\SnortEngine::class);
            if (!$snort->isInstalled()) {
                return;
            }

            // Find local Snort rules directories
            $rulesDirs = [];
            if (PHP_OS_FAMILY === 'Windows') {
                $rulesDirs = ['C:\\Snort\\rules'];
            } else {
                $rulesDirs = ['/etc/snort/rules', '/usr/local/etc/snort/rules'];
            }

            $rules = [];
            foreach ($rulesDirs as $dir) {
                if (!is_dir($dir)) {
                    continue;
                }

                $files = glob($dir . DIRECTORY_SEPARATOR . '*.rules');
                foreach ($files as $file) {
                    // Skip hub_custom.rules (those came FROM Hub)
                    if (str_contains(basename($file), 'hub_custom')) {
                        continue;
                    }

                    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    foreach ($lines as $line) {
                        $line = trim($line);
                        // Skip comments and empty lines
                        if (empty($line) || $line[0] === '#') {
                            continue;
                        }

                        // Parse SID from rule content
                        if (preg_match('/sid\s*:\s*(\d+)/', $line, $sidMatch)) {
                            $sid = (int) $sidMatch[1];

                            // Parse name/msg
                            $name = '';
                            if (preg_match('/msg\s*:\s*"([^"]*)"/', $line, $msgMatch)) {
                                $name = $msgMatch[1];
                            }

                            // Parse action (alert, drop, pass, etc.)
                            $action = 'alert';
                            if (preg_match('/^(alert|drop|pass|log|activate|dynamic|reject|sdrop)\s+/', $line, $actionMatch)) {
                                $action = $actionMatch[1];
                            }

                            // Parse category from classtype
                            $category = basename($file, '.rules');
                            if (preg_match('/classtype\s*:\s*([^;]+)/', $line, $classMatch)) {
                                $category = trim($classMatch[1]);
                            }

                            // Parse priority
                            $priority = 1;
                            if (preg_match('/priority\s*:\s*(\d+)/', $line, $priMatch)) {
                                $priority = (int) $priMatch[1];
                            }

                            // Map priority to severity
                            $severity = match (true) {
                                $priority >= 4 => 'critical',
                                $priority >= 3 => 'high',
                                $priority >= 2 => 'medium',
                                default => 'low',
                            };

                            $rules[] = [
                                'sid' => $sid,
                                'name' => $name ?: "Rule SID:{$sid}",
                                'category' => $category,
                                'rule_content' => $line,
                                'action' => $action,
                                'severity' => $severity,
                                'priority' => $priority,
                            ];
                        }
                    }
                }
            }

            if (empty($rules)) {
                Log::debug('No local Snort rules to upload to Hub');
                return;
            }

            // Upload in batches of 100
            $batches = array_chunk($rules, 100);
            $totalImported = 0;

            foreach ($batches as $batch) {
                $response = \Illuminate\Support\Facades\Http::timeout(60)
                    ->withHeaders(['Authorization' => "Bearer {$this->agentToken}"])
                    ->post("{$this->wafUrl}/api/ids/agents/snort-rules/upload", [
                        'token' => $this->agentToken,
                        'rules' => $batch,
                    ]);

                if ($response->successful()) {
                    $data = $response->json();
                    $totalImported += ($data['imported'] ?? 0);
                } else {
                    Log::warning('Failed to upload Snort rules batch to Hub', [
                        'status' => $response->status(),
                    ]);
                }
            }

            if ($totalImported > 0) {
                Log::info("Uploaded {$totalImported} Snort rules to Hub");
                $this->reportAgentEvent('snort_rule_sync', "已上傳 {$totalImported} 條本地 Snort 規則到 Hub", [
                    'total_rules' => count($rules),
                    'imported' => $totalImported,
                ]);
            }

        } catch (\Exception $e) {
            Log::error('Failed to upload Snort rules to Hub: ' . $e->getMessage());
        }
    }

    /**
     * Report an event to the Hub
     */
    private function reportAgentEvent(string $eventType, string $message, array $details = []): void
    {
        try {
            if (empty($this->wafUrl) || empty($this->agentToken)) {
                Log::warning('Cannot report event: Hub URL or token not configured');
                return;
            }

            \Illuminate\Support\Facades\Http::timeout(10)
                ->post("{$this->wafUrl}/api/ids/agents/events", [
                    'token' => $this->agentToken,
                    'events' => [
                        [
                            'event_type' => $eventType,
                            'message' => $message,
                            'details' => $details ?: null,
                            'created_at' => now()->toIso8601String(),
                        ],
                    ],
                ]);
        } catch (\Exception $e) {
            Log::warning('Failed to report event to Hub: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle virus definitions update signal from Hub
     */
    private function handleDefinitionsUpdate(): void
    {
        try {
            Log::info('Virus definitions update signal received, running freshclam...');
            
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::warning('ClamAV not installed, cannot update definitions');
                return;
            }
            
            // Run freshclam to update virus definitions
            $result = $clamav->updateDefinitions();
            
            if ($result['success']) {
                Log::info('Virus definitions updated successfully', [
                    'definitions_date' => $result['definitions_date'] ?? 'unknown',
                ]);
                
                // Report new definitions date to Hub
                $clamav->reportToHub([
                    'definitions_date' => $result['definitions_date'] ?? null,
                    'status' => 'healthy',
                ]);
            } else {
                Log::error('Virus definitions update failed: ' . ($result['message'] ?? 'Unknown error'));
            }
            
        } catch (\Exception $e) {
            Log::error('Definitions update failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle system reboot signal from WAF Hub
     */
    private function handleSystemReboot(): void
    {
        try {
            echo "⚠️ REBOOT SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('System reboot initiated by WAF Hub remote command');
            
            // Write to a file log that works even in scheduled task context
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\reboot.log'
                : base_path('storage/logs/reboot.log');
            $timestamp = date('Y-m-d H:i:s');
            file_put_contents($logFile, "[{$timestamp}] Reboot signal received from WAF Hub\n", FILE_APPEND);
            
            // Small delay to allow log to be written
            sleep(2);
            
            if (PHP_OS_FAMILY === 'Windows') {
                // Windows: Create a one-time scheduled task to reboot
                // This is more reliable than direct exec() in scheduled task context
                echo "🔄 Executing Windows restart command...\n";
                Log::info('Executing Windows restart command...');
                file_put_contents($logFile, "[{$timestamp}] Executing Windows restart via schtasks...\n", FILE_APPEND);
                
                $output = [];
                $returnCode = 0;
                
                // Method 1: Create a one-time scheduled task to run shutdown
                // This bypasses any exec() restrictions in the current scheduled task context
                $taskName = 'SecurityOneIDS-Reboot-' . time();
                $rebootTime = date('H:i', strtotime('+1 minute'));
                $rebootDate = date('Y/m/d');
                
                // Create task
                $createCommand = "schtasks /create /tn \"{$taskName}\" /tr \"shutdown /r /t 5 /f /c \\\"Security One IDS: Remote Reboot\\\"\" /sc once /st {$rebootTime} /sd {$rebootDate} /f /ru SYSTEM";
                exec($createCommand . ' 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] schtasks create result: code={$returnCode}, output=" . implode(' ', $output) . "\n", FILE_APPEND);
                
                if ($returnCode === 0) {
                    // Run the task immediately
                    $output = [];
                    exec("schtasks /run /tn \"{$taskName}\" 2>&1", $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] schtasks run result: code={$returnCode}, output=" . implode(' ', $output) . "\n", FILE_APPEND);
                }
                
                // Fallback: try direct shutdown if schtasks failed
                if ($returnCode !== 0) {
                    file_put_contents($logFile, "[{$timestamp}] schtasks failed, trying direct shutdown...\n", FILE_APPEND);
                    $output = [];
                    exec('C:\\Windows\\System32\\shutdown.exe /r /t 10 /f 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] Direct shutdown result: code={$returnCode}, output=" . implode(' ', $output) . "\n", FILE_APPEND);
                }
                
                // Last resort: PowerShell
                if ($returnCode !== 0) {
                    file_put_contents($logFile, "[{$timestamp}] Trying PowerShell...\n", FILE_APPEND);
                    exec('powershell -Command "Restart-Computer -Force" 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] PowerShell result: code={$returnCode}\n", FILE_APPEND);
                }
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                // macOS: Use shutdown command directly (osascript requires GUI session)
                echo "🔄 Executing macOS restart command...\n";
                Log::info('Executing macOS restart command...');
                file_put_contents($logFile, "[{$timestamp}] Executing macOS restart...\n", FILE_APPEND);
                
                // For launchd service, use shutdown command directly
                // sudo must be configured with NOPASSWD for this user/command
                $output = [];
                $returnCode = 0;
                
                // Method 1: Try shutdown with sudo (launchd runs as root)
                exec('sudo /sbin/shutdown -r now 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] shutdown result: code={$returnCode}, output=" . implode(' ', $output) . "\n", FILE_APPEND);
                
                if ($returnCode !== 0) {
                    // Method 2: Try without sudo (if running as root)
                    exec('/sbin/shutdown -r now 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] shutdown (no sudo) result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 3: Try reboot command
                    exec('sudo /sbin/reboot 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] reboot result: code={$returnCode}\n", FILE_APPEND);
                }
                
            } else {
                // Linux: Use shutdown command
                echo "🔄 Executing Linux restart command...\n";
                Log::info('Executing Linux restart command...');
                exec('sudo shutdown -r +1 "Security One IDS Agent: Reboot requested by WAF Hub" 2>&1 &');
            }
            
            echo "✅ Reboot command dispatched\n";
            Log::info('Reboot command dispatched');
            file_put_contents($logFile, "[{$timestamp}] Reboot command dispatched successfully\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to execute reboot: " . $e->getMessage() . "\n";
            Log::error('Failed to execute reboot: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle system lock signal from WAF Hub
     * Locks the screen to prevent login
     */
    private function handleSystemLock(): void
    {
        try {
            echo "⚠️ LOCK SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('System lock initiated by WAF Hub remote command');
            
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\lock.log'
                : base_path('storage/logs/lock.log');
            $timestamp = date('Y-m-d H:i:s');
            
            // Ensure log directory exists
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            file_put_contents($logFile, "[{$timestamp}] Lock signal received from WAF Hub\n", FILE_APPEND);
            
            if (PHP_OS_FAMILY === 'Windows') {
                // Windows: Lock workstation
                // Note: LockWorkStation() API doesn't work from Session 0 (service)
                // We need to run the lock command in the user's interactive session
                echo "🔒 Executing Windows lock command...\n";
                Log::info('Executing Windows lock command...');
                file_put_contents($logFile, "[{$timestamp}] Executing Windows lock...\n", FILE_APPEND);
                
                $output = [];
                $returnCode = 1;
                
                // Step 1: Find the currently logged-in user using multiple methods
                $userOutput = [];
                $username = null;
                
                // Method 1: Try query user (Windows Pro/Enterprise with RDS)
                exec('query user 2>&1', $userOutput, $rc);
                file_put_contents($logFile, "[{$timestamp}] query user output: " . implode(" ", $userOutput) . "\n", FILE_APPEND);
                
                foreach ($userOutput as $line) {
                    if (preg_match('/^>?(\S+)\s+\S+\s+\d+\s+Active/i', trim($line), $matches)) {
                        $username = $matches[1];
                        break;
                    }
                }
                
                // Method 2: Use wmic to get logged-in users
                if (!$username) {
                    $userOutput = [];
                    exec('wmic computersystem get username 2>&1', $userOutput, $rc);
                    file_put_contents($logFile, "[{$timestamp}] wmic username output: " . implode(" ", $userOutput) . "\n", FILE_APPEND);
                    foreach ($userOutput as $line) {
                        $line = trim($line);
                        // Format: DOMAIN\username or just username
                        if ($line && $line !== 'UserName' && stripos($line, 'username') === false) {
                            // Extract just the username part (after backslash if present)
                            if (strpos($line, '\\') !== false) {
                                $username = substr($line, strrpos($line, '\\') + 1);
                            } else {
                                $username = $line;
                            }
                            break;
                        }
                    }
                }
                
                // Method 3: Find explorer.exe owner
                if (!$username) {
                    $userOutput = [];
                    exec('tasklist /FI "IMAGENAME eq explorer.exe" /FO CSV /NH 2>&1', $userOutput, $rc);
                    file_put_contents($logFile, "[{$timestamp}] tasklist output: " . implode(" ", $userOutput) . "\n", FILE_APPEND);
                    // If explorer.exe is running, someone is logged in
                    if (!empty($userOutput) && strpos($userOutput[0], 'explorer.exe') !== false) {
                        // Get username from environment
                        $username = getenv('USERNAME') ?: null;
                    }
                }
                
                file_put_contents($logFile, "[{$timestamp}] Found active user: " . ($username ?? 'none') . "\n", FILE_APPEND);
                
                if ($username) {
                    // Method 1: Create scheduled task that runs as the interactive user
                    $lockScript = 'C:\\ProgramData\\SecurityOneIDS\\lock.vbs';
                    // Use VBScript which can interact with the desktop
                    $vbsContent = 'CreateObject("Wscript.Shell").Run "rundll32.exe user32.dll,LockWorkStation", 0, False';
                    file_put_contents($lockScript, $vbsContent);
                    
                    // Create task that runs as INTERACTIVE user (the one currently logged in)
                    $createCmd = 'schtasks /Create /TN "SecurityOneLock" /TR "wscript.exe \"' . $lockScript . '\"" /SC ONCE /ST 00:00 /F /RU "' . $username . '" /IT';
                    exec($createCmd . ' 2>&1', $output, $rc1);
                    file_put_contents($logFile, "[{$timestamp}] schtasks create for user '{$username}': code={$rc1}, output=" . implode(" ", array_slice($output, -3)) . "\n", FILE_APPEND);
                    
                    if ($rc1 === 0) {
                        // Run the task
                        exec('schtasks /Run /TN "SecurityOneLock" 2>&1', $output, $returnCode);
                        file_put_contents($logFile, "[{$timestamp}] schtasks run: code={$returnCode}\n", FILE_APPEND);
                        
                        // Wait and cleanup
                        sleep(3);
                        exec('schtasks /Delete /TN "SecurityOneLock" /F 2>&1');
                    }
                    @unlink($lockScript);
                }
                
                // Method 2: Try using logoff (more drastic but reliable)
                if ($returnCode !== 0) {
                    // Use msg command to notify then lock - this reaches interactive session
                    exec('msg * /TIME:1 "System will lock in 1 second..." 2>&1', $output, $rc);
                    sleep(1);
                    // Create a batch file and run via scheduled task with SYSTEM and /IT
                    $batchFile = 'C:\\ProgramData\\SecurityOneIDS\\lock.bat';
                    file_put_contents($batchFile, '@echo off' . "\r\n" . 'rundll32.exe user32.dll,LockWorkStation');
                    exec('schtasks /Create /TN "SysLock" /TR "' . $batchFile . '" /SC ONCE /ST 00:00 /F /RU SYSTEM /IT 2>&1', $output, $rc1);
                    exec('schtasks /Run /TN "SysLock" 2>&1', $output, $returnCode);
                    sleep(2);
                    exec('schtasks /Delete /TN "SysLock" /F 2>&1');
                    @unlink($batchFile);
                    file_put_contents($logFile, "[{$timestamp}] SYSTEM scheduled task result: code={$returnCode}\n", FILE_APPEND);
                }
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                // macOS: Lock screen properly (not just sleep display)
                echo "🔒 Executing macOS lock command...\n";
                Log::info('Executing macOS lock command...');
                file_put_contents($logFile, "[{$timestamp}] Executing macOS lock...\n", FILE_APPEND);
                
                $output = [];
                $returnCode = 1;
                
                // Method 1: CGSession -suspend - this is the proper lock command
                // This immediately locks the screen and requires password to unlock
                exec('/System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] CGSession -suspend result: code={$returnCode}\n", FILE_APPEND);
                
                if ($returnCode !== 0) {
                    // Method 2: Use osascript to simulate Ctrl+Command+Q (lock screen shortcut)
                    exec('osascript -e \'tell application "System Events" to keystroke "q" using {command down, control down}\' 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] osascript keystroke result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 3: Start screen saver (locks if password is required)
                    exec('osascript -e \'tell application "System Events" to start current screen saver\' 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] screen saver result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 4: pmset displaysleepnow as fallback
                    exec('pmset displaysleepnow 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] pmset result: code={$returnCode}\n", FILE_APPEND);
                }
                
            } else {
                // Linux: Try multiple methods
                echo "🔒 Executing Linux lock command...\n";
                Log::info('Executing Linux lock command...');
                file_put_contents($logFile, "[{$timestamp}] Executing Linux lock...\n", FILE_APPEND);
                
                // Method 1: loginctl (systemd-based systems)
                $output = [];
                $returnCode = 0;
                exec('loginctl lock-sessions 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] loginctl result: code={$returnCode}\n", FILE_APPEND);
                
                if ($returnCode !== 0) {
                    // Method 2: dm-tool (LightDM)
                    exec('dm-tool lock 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] dm-tool result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 3: gnome-screensaver
                    exec('gnome-screensaver-command -l 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] gnome-screensaver result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 4: xdg-screensaver
                    exec('xdg-screensaver lock 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] xdg-screensaver result: code={$returnCode}\n", FILE_APPEND);
                }
            }
            
            echo "✅ Lock command dispatched\n";
            Log::info('Lock command dispatched');
            file_put_contents($logFile, "[{$timestamp}] Lock command dispatched successfully\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to execute lock: " . $e->getMessage() . "\n";
            Log::error('Failed to execute lock: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle system unlock signal from WAF Hub
     * Attempts to unlock the screen (limited by OS security)
     */
    private function handleSystemUnlock(): void
    {
        try {
            echo "⚠️ UNLOCK SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('System unlock initiated by WAF Hub remote command');
            
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\unlock.log'
                : base_path('storage/logs/unlock.log');
            $timestamp = date('Y-m-d H:i:s');
            
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            file_put_contents($logFile, "[{$timestamp}] Unlock signal received from WAF Hub\n", FILE_APPEND);
            
            // Note: Most OS don't allow remote unlock without password for security
            // This will attempt to activate/wake the display
            if (PHP_OS_FAMILY === 'Windows') {
                echo "🔓 Attempting Windows unlock (waking display)...\n";
                // Send key press to wake display
                exec('powershell -Command "[System.Windows.Forms.SendKeys]::SendWait(\' \')"  2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Windows wake result: code={$returnCode}\n", FILE_APPEND);
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                echo "🔓 Attempting macOS unlock (waking display)...\n";
                exec('caffeinate -u -t 1 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] macOS caffeinate result: code={$returnCode}\n", FILE_APPEND);
                
            } else {
                echo "🔓 Attempting Linux unlock...\n";
                exec('loginctl unlock-sessions 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Linux unlock result: code={$returnCode}\n", FILE_APPEND);
            }
            
            echo "✅ Unlock command dispatched\n";
            Log::info('Unlock command dispatched');
            file_put_contents($logFile, "[{$timestamp}] Unlock command dispatched\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to execute unlock: " . $e->getMessage() . "\n";
            Log::error('Failed to execute unlock: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle disable login signal from WAF Hub
     * Disables password authentication for all users
     */
    private function handleDisableLogin(): void
    {
        try {
            echo "⚠️ DISABLE LOGIN SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('Disable login initiated by WAF Hub remote command');
            
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\login_control.log'
                : base_path('storage/logs/login_control.log');
            $timestamp = date('Y-m-d H:i:s');
            
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            file_put_contents($logFile, "[{$timestamp}] Disable login signal received from WAF Hub\n", FILE_APPEND);
            
            if (PHP_OS_FAMILY === 'Windows') {
                echo "🚫 Disabling Windows user accounts...\n";
                // Disable all non-system user accounts
                exec('powershell -Command "Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -ne \'Administrator\'} | Disable-LocalUser" 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Windows disable users result: code={$returnCode}\n", FILE_APPEND);
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                echo "🚫 Disabling macOS user login...\n";
                // Get current console user (may be different from running user)
                $consoleUser = trim(exec("stat -f '%Su' /dev/console 2>/dev/null") ?: '');
                file_put_contents($logFile, "[{$timestamp}] Console user: {$consoleUser}\n", FILE_APPEND);
                
                if ($consoleUser && $consoleUser !== 'root' && $consoleUser !== '_mbsetupuser') {
                    // Method 1: Use dscl to disable user account
                    // The correct way is to set AuthenticationAuthority to DisabledUser
                    $output = [];
                    exec("sudo dscl . -create /Users/{$consoleUser} AuthenticationAuthority ';DisabledUser;' 2>&1", $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] dscl disable user {$consoleUser}: code={$returnCode}, output=" . implode(" ", $output) . "\n", FILE_APPEND);
                    
                    if ($returnCode !== 0) {
                        // Method 2: Lock the user's password (they won't be able to login)
                        exec("sudo pwpolicy -u {$consoleUser} disableuser 2>&1", $output, $returnCode);
                        file_put_contents($logFile, "[{$timestamp}] pwpolicy disable user: code={$returnCode}\n", FILE_APPEND);
                    }
                    
                    if ($returnCode !== 0) {
                        // Method 3: Set an impossible password hash
                        exec("sudo dscl . -passwd /Users/{$consoleUser} '*' 2>&1", $output, $returnCode);
                        file_put_contents($logFile, "[{$timestamp}] dscl set impossible password: code={$returnCode}\n", FILE_APPEND);
                    }
                } else {
                    file_put_contents($logFile, "[{$timestamp}] No valid console user found to disable\n", FILE_APPEND);
                }
                
            } else {
                echo "🚫 Disabling Linux user login...\n";
                // Lock all non-root users
                exec('for user in $(awk -F: \'$3 >= 1000 && $3 < 65534 {print $1}\' /etc/passwd); do passwd -l "$user" 2>/dev/null; done', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Linux disable users result: code={$returnCode}\n", FILE_APPEND);
            }
            
            echo "✅ Login disabled\n";
            Log::info('Login disabled');
            file_put_contents($logFile, "[{$timestamp}] Login disabled successfully\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to disable login: " . $e->getMessage() . "\n";
            Log::error('Failed to disable login: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle enable login signal from WAF Hub
     * Restores password authentication for all users
     */
    private function handleEnableLogin(): void
    {
        try {
            echo "⚠️ ENABLE LOGIN SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('Enable login initiated by WAF Hub remote command');
            
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\login_control.log'
                : base_path('storage/logs/login_control.log');
            $timestamp = date('Y-m-d H:i:s');
            
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            file_put_contents($logFile, "[{$timestamp}] Enable login signal received from WAF Hub\n", FILE_APPEND);
            
            if (PHP_OS_FAMILY === 'Windows') {
                echo "✅ Enabling Windows user accounts...\n";
                // Enable previously disabled users, but exclude system accounts (Guest, Administrator)
                exec('powershell -Command "Get-LocalUser | Where-Object {$_.Enabled -eq $false -and $_.Name -ne \'Guest\' -and $_.Name -ne \'Administrator\'} | Enable-LocalUser" 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Windows enable users result: code={$returnCode}\n", FILE_APPEND);
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                echo "✅ Enabling macOS user login...\n";
                // Get all regular users and enable them
                $usersOutput = [];
                exec("dscl . -list /Users | grep -v '^_' | grep -v 'daemon' | grep -v 'nobody' | grep -v 'root' 2>/dev/null", $usersOutput, $rc);
                
                foreach ($usersOutput as $user) {
                    $user = trim($user);
                    if (!$user) continue;
                    
                    // Remove DisabledUser from AuthenticationAuthority
                    exec("sudo dscl . -delete /Users/{$user} AuthenticationAuthority 2>&1", $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] dscl clear auth for {$user}: code={$returnCode}\n", FILE_APPEND);
                    
                    // Re-enable with pwpolicy  
                    exec("sudo pwpolicy -u {$user} enableuser 2>&1", $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] pwpolicy enable user {$user}: code={$returnCode}\n", FILE_APPEND);
                }
                
            } else {
                echo "✅ Enabling Linux user login...\n";
                exec('for user in $(awk -F: \'$3 >= 1000 && $3 < 65534 {print $1}\' /etc/passwd); do passwd -u "$user" 2>/dev/null; done', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Linux enable users result: code={$returnCode}\n", FILE_APPEND);
            }
            
            echo "✅ Login enabled\n";
            Log::info('Login enabled');
            file_put_contents($logFile, "[{$timestamp}] Login enabled successfully\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to enable login: " . $e->getMessage() . "\n";
            Log::error('Failed to enable login: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle blocked IPs from WAF Hub
     * Syncs the list of IPs that should be blocked locally
     */
    private function handleBlockedIps(array $blockedIps): void
    {
        try {
            $blockingService = app(\App\Services\BlockingService::class);
            $localBlocked = $blockingService->getBlockedIPs();
            
            $hubIps = array_column($blockedIps, 'ip');
            $localIps = array_keys($localBlocked);
            
            // Block new IPs from Hub
            $newBlocks = array_diff($hubIps, $localIps);
            foreach ($newBlocks as $ip) {
                $blockData = collect($blockedIps)->firstWhere('ip', $ip);
                if ($blockData) {
                    Log::info("Blocking IP from WAF Hub: {$ip}", ['reason' => $blockData['reason']]);
                    echo "🚫 Blocking IP from Hub: {$ip}\n";
                    $blockingService->blockIP(
                        $ip,
                        $blockData['reason'] ?? 'Blocked by WAF Hub',
                        'high',
                        $blockData['duration'] ?? null
                    );
                }
            }
            
            // Unblock IPs that are no longer in Hub list
            $staleBlocks = array_diff($localIps, $hubIps);
            foreach ($staleBlocks as $ip) {
                // Only unblock if it was originally from Hub (check reason)
                if (isset($localBlocked[$ip]) && str_contains($localBlocked[$ip]['reason'] ?? '', 'Hub')) {
                    Log::info("Unblocking IP removed from WAF Hub: {$ip}");
                    echo "✅ Unblocking IP (removed from Hub): {$ip}\n";
                    $blockingService->unblockIP($ip);
                }
            }
            
            if (count($newBlocks) > 0 || count($staleBlocks) > 0) {
                Log::info('Blocked IPs synced from WAF Hub', [
                    'new_blocks' => count($newBlocks),
                    'removed_blocks' => count($staleBlocks),
                    'total_active' => count($hubIps),
                ]);
            }
            
        } catch (\Exception $e) {
            Log::error('Failed to handle blocked IPs: ' . $e->getMessage());
        }
    }
    
    /**
     * Check if remote has newer code and auto-update if needed
     *
     * Compares local HEAD commit hash against origin/main.
     * No version number comparison — purely git commit based.
     */
    private function checkAndAutoUpdate(): void
    {
        try {
            $installDir = base_path();

            // Throttle: only check once every 5 minutes
            $lastCheckFile = storage_path('app/last_auto_update_check.txt');
            if (file_exists($lastCheckFile)) {
                $lastCheck = (int) file_get_contents($lastCheckFile);
                if (time() - $lastCheck < 300) {
                    return;
                }
            }
            file_put_contents($lastCheckFile, time());

            // Fetch latest from remote (lightweight operation)
            $fetchResult = Process::path($installDir)
                ->timeout(30)
                ->run('git fetch origin main 2>&1');

            if (!$fetchResult->successful()) {
                Log::debug('Auto-update: git fetch failed', ['output' => $fetchResult->output()]);
                return;
            }

            // Compare local HEAD vs remote HEAD
            $localHash = trim(Process::path($installDir)
                ->run('git rev-parse HEAD 2>/dev/null')
                ->output());

            $remoteHash = trim(Process::path($installDir)
                ->run('git rev-parse origin/main 2>/dev/null')
                ->output());

            if (empty($localHash) || empty($remoteHash)) {
                return;
            }

            if ($localHash === $remoteHash) {
                Log::debug('Auto-update: already up to date', ['hash' => substr($localHash, 0, 8)]);
                return;
            }

            Log::info('Auto-update: new code detected, updating...', [
                'local' => substr($localHash, 0, 8),
                'remote' => substr($remoteHash, 0, 8),
            ]);

            $this->reportAgentEvent('code_update', 'Auto-update: detecting new code version, updating...');
            $this->handleIdsUpdate();

        } catch (\Exception $e) {
            Log::debug('Auto-update check failed: ' . $e->getMessage());
        }
    }

    /**
     * Handle IDS update signal
     */
    private function handleIdsUpdate(): void
    {
        try {
            Log::info('IDS update signal received, starting update...');
            
            // Report "updating" status to WAF Hub
            $this->reportUpdateStatus('updating');
            
            // Get install directory and detect platform
            $installDir = base_path();
            $isWindows = PHP_OS_FAMILY === 'Windows';
            $isDocker = file_exists('/.dockerenv') || getenv('DOCKER_CONTAINER');
            
            // Force update: fetch + reset --hard to avoid conflicts with local changes
            Log::info('Fetching latest code from git...', ['platform' => $isWindows ? 'windows' : 'unix']);
            
            if ($isWindows) {
                // Windows: Use cmd.exe for better output capturing
                $gitResult = Process::path($installDir)
                    ->timeout(300)
                    ->run('cmd /c "git fetch origin main 2>&1 && git reset --hard origin/main 2>&1"');
                
                // Log both output and error for debugging
                Log::info('Git command completed', [
                    'output' => $gitResult->output(),
                    'error' => $gitResult->errorOutput(),
                    'exitCode' => $gitResult->exitCode(),
                ]);
            } else {
                // Clean untracked files that might conflict, then force update
                Process::path($installDir)
                    ->timeout(30)
                    ->run('git clean -fd 2>&1');
                    
                $gitResult = Process::path($installDir)
                    ->timeout(300)
                    ->run('git fetch origin main 2>&1 && git reset --hard origin/main 2>&1');
            }
            
            if (!$gitResult->successful()) {
                $errorMsg = $gitResult->output() ?: $gitResult->errorOutput() ?: 'Unknown error (exit code: ' . $gitResult->exitCode() . ')';
                Log::error('Git pull failed: ' . $errorMsg);
                $this->reportUpdateStatus('error');
                return;
            }
            
            Log::info('Git pull successful', ['output' => $gitResult->output()]);
            
            // Clear Snort install failure cache — new code might fix the issue
            @unlink(storage_path('app/snort_install_failed.txt'));

            // Clear Snort rules hash — force re-sync so updated converter re-processes rules
            @unlink(storage_path('app/snort_rules_hash.txt'));
            Log::info('Cleared Snort rules hash to force re-conversion with updated code');
            
            // Run composer install
            Log::info('Running composer install...');
            
            if ($isWindows) {
                // Windows: Find composer and run with PowerShell
                $composerCmd = 'composer';
                
                // Check if composer.phar exists in directory
                if (file_exists($installDir . '/composer.phar')) {
                    $composerCmd = 'php composer.phar';
                } elseif (file_exists($installDir . '/composer.bat')) {
                    $composerCmd = 'composer.bat';
                }
                
                $composerResult = Process::path($installDir)
                    ->timeout(600)
                    ->env(['COMPOSER_ALLOW_SUPERUSER' => '1'])
                    ->run("powershell -Command \"{$composerCmd} install --no-interaction --no-dev --optimize-autoloader 2>&1\"");
            } else {
                $homeDir = getenv('HOME') ?: (PHP_OS_FAMILY === 'Darwin' ? '/Users/' . get_current_user() : '/home/' . get_current_user());
                $composerResult = Process::path($installDir)
                    ->timeout(600)
                    ->env([
                        'HOME' => $homeDir,
                        'COMPOSER_HOME' => $homeDir . '/.composer',
                        'COMPOSER_ALLOW_SUPERUSER' => '1',
                    ])
                    ->run('composer install --no-interaction --no-dev --optimize-autoloader 2>&1');
            }
            
            if (!$composerResult->successful()) {
                Log::warning('Composer install warning: ' . $composerResult->output());
                // Continue anyway, might just be warnings
            }
            
            // Run database migrations if any
            Log::info('Running database migrations...');
            Artisan::call('migrate', ['--force' => true]);
            
            // Clear caches
            Log::info('Clearing caches...');
            Artisan::call('config:clear');
            Artisan::call('cache:clear');
            
            // Handle environment-specific restart
            if ($isDocker) {
                Log::info('Docker environment detected, triggering container rebuild...');
                
                $rebuildScript = $installDir . '/docker/rebuild.sh';
                if (file_exists($rebuildScript)) {
                    Log::info('Running Docker rebuild script...');
                    exec("nohup bash {$rebuildScript} >> /var/www/html/storage/logs/docker-rebuild.log 2>&1 &");
                } else {
                    file_put_contents($installDir . '/storage/rebuild_requested', date('Y-m-d H:i:s'));
                    Log::info('Docker rebuild marker created, waiting for external rebuild...');
                }
            } elseif ($isWindows) {
                // Windows: Restart PHP process or Windows service if applicable
                Log::info('Windows update completed, regenerating sync script...');
                
                // Regenerate the sync service script with latest template
                $this->regenerateWindowsSyncScript($installDir);
                
                Log::info('Windows sync script regenerated, no automatic restart required');
                // Note: Windows Agent typically runs as a scheduled task or service
                // The next heartbeat will pick up the new code
            }
            
            // Get new version from config
            $newVersion = config('ids.version') ?? '1.0.0';
            
            Log::info('IDS update completed successfully', ['new_version' => $newVersion]);
            
            // Mark that code was updated — skip rule sync in this cycle
            // because PHP still has old classes in memory
            $this->codeUpdated = true;
            
            // Report "completed" status to WAF Hub with new version
            $this->reportUpdateStatus('completed', $newVersion);
            
            // Mark update as processed locally
            $configPath = storage_path('app/waf_config.json');
            if (file_exists($configPath)) {
                $config = json_decode(file_get_contents($configPath), true) ?: [];
                unset($config['addons']['update_ids']);
                file_put_contents($configPath, json_encode($config, JSON_PRETTY_PRINT));
            }
        } catch (\Exception $e) {
            Log::error('IDS update failed: ' . $e->getMessage());
            $this->reportUpdateStatus('error');
        }
    }
    
    /**
     * Report update status to WAF Hub
     */
    private function reportUpdateStatus(string $status, ?string $version = null): void
    {
        try {
            $wafUrl = rtrim(config('ids.waf_url') ?? env('WAF_URL', ''), '/');
            
            // Read token from .env
            $envPath = base_path('.env');
            $token = env('AGENT_TOKEN', '');
            
            if (empty($token) && file_exists($envPath)) {
                $envContent = file_get_contents($envPath);
                if (preg_match('/^AGENT_TOKEN=(.*)$/m', $envContent, $matches)) {
                    $token = trim($matches[1], '"\'');
                }
            }
            
            if (empty($wafUrl) || empty($token)) {
                Log::warning('Cannot report update status: WAF not configured');
                return;
            }
            
            $payload = [
                'update_status' => $status,
            ];
            
            if ($version) {
                $payload['version'] = $version;
            }
            
            $response = $this->getHttpClient(30)
                ->withToken($token)
                ->post("{$wafUrl}/api/ids/agents/update-status", $payload);
            
            if ($response->successful()) {
                Log::info("Update status '{$status}' reported successfully");
            } else {
                Log::error('Failed to report update status', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);
            }
        } catch (\Exception $e) {
            Log::error('Failed to report update status: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle scan now signal from WAF Hub
     */
    private function handleScanNow(): void
    {
        try {
            Log::info('Scan now signal received, starting ClamAV scan...');
            
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::warning('ClamAV not installed, cannot perform scan');
                return;
            }
            
            // Use platform-specific scan paths
            $platform = PHP_OS_FAMILY === 'Darwin' ? 'macos' : 'linux';
            
            if ($platform === 'macos') {
                $scanPaths = [
                    '/Users',
                    '/Applications',
                    '/tmp',
                ];
            } else {
                $scanPaths = [
                    '/home',
                    '/var/www',
                    '/tmp',
                ];
            }
            
            Log::info("Starting ClamAV scan on {$platform}", ['paths' => $scanPaths]);
            
            // Send "scanning" status to WAF Hub immediately
            $clamav->reportToHub(['scan_status' => 'scanning']);
            
            $allResults = [
                'last_scan' => now()->toDateTimeString(),
                'infected_files' => 0,
                'scanned_files' => 0,
                'threats' => [],
                'scan_status' => 'scanning',
            ];
            
            foreach ($scanPaths as $path) {
                if (is_dir($path)) {
                    Log::info("Scanning directory: {$path}");
                    $result = $clamav->scan($path);
                    
                    if ($result['success']) {
                        $allResults['scanned_files'] += $result['scanned_files'] ?? 0;
                        $allResults['infected_files'] += $result['infected_files'] ?? 0;
                        $allResults['threats'] = array_merge($allResults['threats'], $result['threats'] ?? []);
                    }
                }
            }
            
            Log::info('ClamAV scan completed', [
                'scanned_files' => $allResults['scanned_files'],
                'infected_files' => $allResults['infected_files'],
            ]);
            
            // Report completed results to WAF Hub with idle status
            $allResults['scan_status'] = 'idle';
            $clamav->reportToHub($allResults);
            
        } catch (\Exception $e) {
            Log::error('Scan now failed: ' . $e->getMessage());
            
            // Report error status
            try {
                $clamav = app(\App\Services\ClamavService::class);
                $clamav->reportToHub(['scan_status' => 'idle']);
            } catch (\Exception $ex) {
                // Ignore
            }
        }
    }

    /**
     * Get synced config from local storage
     */
    public function getSyncedConfig(): array
    {
        $configPath = storage_path('app/waf_config.json');
        
        if (file_exists($configPath)) {
            return json_decode(file_get_contents($configPath), true) ?: [];
        }
        
        return [];
    }

    /**
     * Report alerts to WAF
     */
    public function reportAlerts(array $alerts): bool
    {
        if (empty($this->wafUrl) || empty($this->agentToken) || empty($alerts)) {
            return false;
        }

        try {
            $response = $this->getHttpClient(30)->post("{$this->wafUrl}/api/ids/agents/alerts", [
                'token' => $this->agentToken,
                'alerts' => $alerts,
            ]);

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Failed to report alerts: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch rules from WAF
     */
    public function fetchRules(): ?array
    {
        if (empty($this->wafUrl) || empty($this->agentToken)) {
            return null;
        }

        try {
            $response = $this->getHttpClient(30)->get("{$this->wafUrl}/api/ids/agents/rules", [
                'token' => $this->agentToken,
            ]);

            if ($response->successful()) {
                return $response->json();
            }

            return null;
        } catch (\Exception $e) {
            Log::error('Failed to fetch rules: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Sync rules from WAF to local IdsSignature database
     */
    public function syncRulesToDatabase(array $rules): int
    {
        $synced = 0;
        
        foreach ($rules as $rule) {
            try {
                \App\Models\IdsSignature::updateOrCreate(
                    ['name' => $rule['name']],
                    [
                        'description' => $rule['description'] ?? null,
                        'pattern' => $rule['pattern'] ?? '',
                        'category' => $rule['category'] ?? 'general',
                        'severity' => $rule['severity'] ?? 'medium',
                        'match_uri' => true,
                        'match_user_agent' => false,
                        'match_referer' => false,
                        'enabled' => $rule['enabled'] ?? true,
                    ]
                );
                $synced++;
            } catch (\Exception $e) {
                Log::error('Failed to sync rule: ' . ($rule['name'] ?? 'unknown'), [
                    'error' => $e->getMessage(),
                ]);
            }
        }
        
        Log::info("Synced {$synced} rules from WAF to local database");
        return $synced;
    }

    /**
     * Upload local signatures to WAF Hub
     */
    public function uploadSignatures(): int
    {
        if (empty($this->wafUrl)) {
            Log::warning('WAF_URL not configured for upload');
            return 0;
        }

        // Use the WAF-assigned token (from registration) if available
        $token = cache()->get('waf_agent_token', $this->agentToken);
        if (empty($token)) {
            Log::warning('No agent token available for upload');
            return 0;
        }

        // Get all local signatures
        $signatures = \App\Models\IdsSignature::where('enabled', true)->get();
        
        if ($signatures->isEmpty()) {
            Log::info('No signatures to upload');
            return 0;
        }

        try {
            $response = $this->getHttpClient(60)->post("{$this->wafUrl}/api/ids/agents/sync-rules", [
                'token' => $token,
                'signatures' => $signatures->map(fn($sig) => [
                    'name' => $sig->name,
                    'pattern' => $sig->pattern,
                    'category' => $sig->category,
                    'severity' => $sig->severity,
                    'description' => $sig->description,
                ])->toArray(),
            ]);

            if ($response->successful()) {
                $data = $response->json();
                Log::info('Successfully uploaded signatures to WAF', $data);
                return $data['synced'] ?? 0;
            }

            Log::error('Failed to upload signatures', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return 0;
        } catch (\Exception $e) {
            Log::error('Exception during signature upload: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get the last git pull/fetch time from FETCH_HEAD or .git/refs/heads/main
     */
    protected function getLastGitPullTime(): ?string
    {
        $basePath = base_path();
        
        // Check FETCH_HEAD (updated on git fetch/pull)
        $fetchHead = "{$basePath}/.git/FETCH_HEAD";
        if (file_exists($fetchHead)) {
            $mtime = filemtime($fetchHead);
            if ($mtime) {
                return date('Y-m-d H:i:s', $mtime);
            }
        }
        
        // Fallback: check refs/heads/main or master
        $refs = [
            "{$basePath}/.git/refs/heads/main",
            "{$basePath}/.git/refs/heads/master",
        ];
        
        foreach ($refs as $ref) {
            if (file_exists($ref)) {
                $mtime = filemtime($ref);
                if ($mtime) {
                    return date('Y-m-d H:i:s', $mtime);
                }
            }
        }
        
        // Last fallback: use git log to get last commit time
        $output = @shell_exec("cd {$basePath} && git log -1 --format=%ci 2>/dev/null");
        if ($output) {
            return trim($output);
        }
        
        return null;
    }

    /**
     * Get discovered log file paths for heartbeat
     *
     * Cached for 5 minutes to avoid rescanning every heartbeat
     */
    protected function getDiscoveredLogPaths(): array
    {
        $cacheFile = storage_path('app/discovered_logs_cache.json');
        
        // Use cached result if less than 5 minutes old
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 300) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                return $cached;
            }
        }

        try {
            $discovery = app(\App\Services\LogDiscoveryService::class);
            $logs = $discovery->discoverLogFiles()->map(fn($log) => [
                'path' => $log['path'],
                'type' => $log['type'],
                'format' => $log['format'] ?? 'unknown',
                'size' => $log['size'] ?? 0,
            ])->values()->toArray();

            // Cache the result
            file_put_contents($cacheFile, json_encode($logs));

            return $logs;
        } catch (\Exception $e) {
            Log::debug('Log discovery failed: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get system information
     */
    protected function getSystemInfo(): array
    {
        // Include Snort status in system info for Hub
        $snortInfo = $this->getSnortInfo();

        return [
            'os' => PHP_OS,
            'php_version' => PHP_VERSION,
            'memory_usage' => memory_get_usage(true),
            'load_average' => function_exists('sys_getloadavg') ? sys_getloadavg() : [],
            'uptime' => $this->getUptime(),
            // Enhanced system metrics for WAF Hub display
            'cpu' => $this->getCpuUsage(),
            'memory' => $this->getMemoryUsage(),
            'disk' => $this->getDiskUsage(),
            'network' => $this->getNetworkUsage(),
            // Snort IPS status
            'snort' => $snortInfo,
        ];
    }

    /**
     * Get Snort IPS status information for heartbeat
     */
    private function getSnortInfo(): array
    {
        try {
            $snort = app(\App\Services\Detection\SnortEngine::class);
            return $snort->getStatus();
        } catch (\Exception $e) {
            return [
                'installed' => false,
                'version' => null,
                'running' => false,
            ];
        }
    }

    /**
     * Get CPU usage percentage
     */
    protected function getCpuUsage(): array
    {
        $percent = 0;
        
        if (PHP_OS_FAMILY === 'Windows') {
            // Windows: Use wmic
            $output = [];
            @exec('wmic cpu get loadpercentage 2>&1', $output);
            foreach ($output as $line) {
                $line = trim($line);
                if (is_numeric($line)) {
                    $percent = (float) $line;
                    break;
                }
            }
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            // macOS: Use top or ps
            $output = @shell_exec("ps -A -o %cpu | awk '{s+=$1} END {print s}'");
            if ($output) {
                $percent = min(100, (float) trim($output));
            }
        } else {
            // Linux: Read from /proc/stat
            if (file_exists('/proc/stat')) {
                $stat1 = file_get_contents('/proc/stat');
                usleep(100000); // 100ms
                $stat2 = file_get_contents('/proc/stat');
                
                preg_match('/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m', $stat1, $m1);
                preg_match('/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m', $stat2, $m2);
                
                if ($m1 && $m2) {
                    $total1 = $m1[1] + $m1[2] + $m1[3] + $m1[4];
                    $total2 = $m2[1] + $m2[2] + $m2[3] + $m2[4];
                    $idle1 = $m1[4];
                    $idle2 = $m2[4];
                    
                    $totalDiff = $total2 - $total1;
                    $idleDiff = $idle2 - $idle1;
                    
                    if ($totalDiff > 0) {
                        $percent = round((1 - $idleDiff / $totalDiff) * 100, 1);
                    }
                }
            }
        }
        
        return ['percent' => $percent];
    }

    /**
     * Get memory usage
     */
    protected function getMemoryUsage(): array
    {
        $total = 0;
        $used = 0;
        $percent = 0;
        
        if (PHP_OS_FAMILY === 'Windows') {
            // Windows: Use wmic
            $output = [];
            @exec('wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value 2>&1', $output);
            $values = [];
            foreach ($output as $line) {
                if (preg_match('/^(\w+)=(\d+)/', trim($line), $m)) {
                    $values[$m[1]] = (int) $m[2] * 1024; // KB to bytes
                }
            }
            $total = $values['TotalVisibleMemorySize'] ?? 0;
            $free = $values['FreePhysicalMemory'] ?? 0;
            $used = $total - $free;
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            // macOS: Use vm_stat and sysctl
            $vmstat = @shell_exec('vm_stat 2>/dev/null');
            
            // Get page size (typically 4096 or 16384 on ARM Macs)
            $pageSize = 4096;
            if ($vmstat && preg_match('/page size of (\d+) bytes/', $vmstat, $m)) {
                $pageSize = (int) $m[1];
            }
            
            // Get total memory from sysctl
            $totalOutput = @shell_exec('sysctl -n hw.memsize 2>/dev/null');
            $total = $totalOutput ? (int) trim($totalOutput) : 0;
            
            if ($vmstat && $total > 0) {
                // Parse vm_stat - note: output uses "." at end of numbers
                $stats = [];
                preg_match_all('/^(.+?):\s+([\d.]+)/m', $vmstat, $matches, PREG_SET_ORDER);
                foreach ($matches as $match) {
                    $key = trim($match[1]);
                    $value = (int) str_replace('.', '', $match[2]);
                    $stats[$key] = $value;
                }
                
                // Calculate used memory: active + wired + compressed
                $activePages = $stats['Pages active'] ?? 0;
                $wiredPages = $stats['Pages wired down'] ?? 0;
                $compressedPages = $stats['Pages occupied by compressor'] ?? 0;
                
                $usedPages = $activePages + $wiredPages + $compressedPages;
                $used = $usedPages * $pageSize;
            } else {
                // Fallback: use top command
                $topOutput = @shell_exec("top -l 1 -s 0 | grep 'PhysMem' 2>/dev/null");
                if ($topOutput) {
                    // Parse: "PhysMem: 15G used (1234M wired), 1234M unused."
                    if (preg_match('/(\d+)([MG])\s+used/i', $topOutput, $usedMatch)) {
                        $multiplier = strtoupper($usedMatch[2]) === 'G' ? 1073741824 : 1048576;
                        $used = (int) $usedMatch[1] * $multiplier;
                    }
                    if (preg_match('/(\d+)([MG])\s+unused/i', $topOutput, $unusedMatch)) {
                        $multiplier = strtoupper($unusedMatch[2]) === 'G' ? 1073741824 : 1048576;
                        $unused = (int) $unusedMatch[1] * $multiplier;
                        $total = $used + $unused;
                    }
                }
                // If still no total, try system_profiler as last resort
                if ($total === 0) {
                    $profilerOutput = @shell_exec("system_profiler SPHardwareDataType 2>/dev/null | grep 'Memory'");
                    if ($profilerOutput && preg_match('/(\d+)\s*GB/', $profilerOutput, $m)) {
                        $total = (int) $m[1] * 1073741824;
                    }
                }
            }
        } else {
            // Linux: Read from /proc/meminfo
            if (file_exists('/proc/meminfo')) {
                $meminfo = file_get_contents('/proc/meminfo');
                preg_match('/MemTotal:\s+(\d+)/', $meminfo, $totalMatch);
                preg_match('/MemAvailable:\s+(\d+)/', $meminfo, $availMatch);
                
                $total = isset($totalMatch[1]) ? (int) $totalMatch[1] * 1024 : 0;
                $available = isset($availMatch[1]) ? (int) $availMatch[1] * 1024 : 0;
                $used = $total - $available;
            }
        }
        
        if ($total > 0) {
            $percent = round(($used / $total) * 100, 1);
        }
        
        return [
            'total' => $total,
            'used' => $used,
            'percent' => $percent,
        ];
    }

    /**
     * Get disk usage
     */
    protected function getDiskUsage(): array
    {
        $path = PHP_OS_FAMILY === 'Windows' ? 'C:' : '/';
        
        $total = @disk_total_space($path) ?: 0;
        $free = @disk_free_space($path) ?: 0;
        $used = $total - $free;
        $percent = $total > 0 ? round(($used / $total) * 100, 1) : 0;
        
        return [
            'total' => $total,
            'used' => $used,
            'percent' => $percent,
        ];
    }

    /**
     * Get network usage (bytes sent/recv per second)
     */
    protected function getNetworkUsage(): array
    {
        $bytesSent = 0;
        $bytesRecv = 0;
        
        // Use file cache to persist between heartbeats
        $cacheFile = storage_path('app/network_stats_cache.json');
        $lastStats = null;
        $lastTime = null;
        
        Log::debug('getNetworkUsage: starting', ['cacheFile' => $cacheFile, 'exists' => file_exists($cacheFile)]);
        
        if (file_exists($cacheFile)) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if ($cached && isset($cached['stats']) && isset($cached['time'])) {
                $lastStats = $cached['stats'];
                $lastTime = $cached['time'];
                Log::debug('getNetworkUsage: cached data loaded', [
                    'lastStats' => $lastStats,
                    'lastTime' => $lastTime,
                ]);
            }
        }
        
        $currentStats = $this->getNetworkStats();
        $currentTime = microtime(true);
        
        Log::debug('getNetworkUsage: current stats', [
            'currentStats' => $currentStats,
            'currentTime' => $currentTime,
        ]);
        
        if ($lastStats !== null && $lastTime !== null) {
            $timeDiff = $currentTime - $lastTime;
            Log::debug('getNetworkUsage: time diff', ['timeDiff' => $timeDiff]);
            
            // Only calculate if time diff is reasonable (1-600 seconds)
            if ($timeDiff > 1 && $timeDiff < 600) {
                $sentDiff = $currentStats['sent'] - $lastStats['sent'];
                $recvDiff = $currentStats['recv'] - $lastStats['recv'];
                
                Log::debug('getNetworkUsage: diffs', ['sentDiff' => $sentDiff, 'recvDiff' => $recvDiff]);
                
                // Handle counter reset (system reboot)
                if ($sentDiff >= 0 && $recvDiff >= 0) {
                    $bytesSent = (int) ($sentDiff / $timeDiff);
                    $bytesRecv = (int) ($recvDiff / $timeDiff);
                    Log::debug('getNetworkUsage: calculated rates', ['bytesSent' => $bytesSent, 'bytesRecv' => $bytesRecv]);
                }
            } else {
                Log::debug('getNetworkUsage: timeDiff out of range, skipping calculation');
            }
        } else {
            Log::debug('getNetworkUsage: no previous data, first run');
        }
        
        // Save current stats for next call
        $writeResult = file_put_contents($cacheFile, json_encode([
            'stats' => $currentStats,
            'time' => $currentTime,
        ]));
        Log::debug('getNetworkUsage: saved cache', ['writeResult' => $writeResult]);
        
        $result = [
            'bytes_sent' => max(0, $bytesSent),
            'bytes_recv' => max(0, $bytesRecv),
        ];
        Log::debug('getNetworkUsage: returning', $result);
        
        return $result;
    }

    /**
     * Get raw network statistics
     */
    protected function getNetworkStats(): array
    {
        $sent = 0;
        $recv = 0;
        
        // Debug: Log OS detection
        Log::debug('getNetworkStats: OS detection', [
            'PHP_OS_FAMILY' => PHP_OS_FAMILY,
            'PHP_OS' => PHP_OS,
            'php_uname' => php_uname('s'),
        ]);
        
        if (PHP_OS_FAMILY === 'Windows') {
            // Windows: Use netstat
            $output = [];
            @exec('netstat -e 2>&1', $output);
            foreach ($output as $line) {
                if (preg_match('/Bytes\s+(\d+)\s+(\d+)/', $line, $m)) {
                    $recv = (int) $m[1];
                    $sent = (int) $m[2];
                    break;
                }
            }
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            // macOS: Try multiple methods to get network bytes
            Log::debug('macOS network stats: starting collection');
            
            // Method 1: netstat -I for specific interface (most reliable)
            $interfaces = ['en0', 'en1', 'en2', 'en3', 'en4', 'en5'];
            foreach ($interfaces as $iface) {
                $output = @shell_exec("netstat -I $iface -b 2>/dev/null");
                if ($output) {
                    Log::debug("macOS netstat -I $iface output", ['output' => $output]);
                    $lines = explode("\n", trim($output));
                    // Second line contains the data
                    if (isset($lines[1])) {
                        $parts = preg_split('/\s+/', trim($lines[1]));
                        Log::debug("macOS $iface parsed parts", ['parts' => $parts, 'count' => count($parts)]);
                        // Format: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
                        if (count($parts) >= 10 && is_numeric($parts[6]) && is_numeric($parts[9])) {
                            $recv += (int) $parts[6];
                            $sent += (int) $parts[9];
                            Log::debug("macOS $iface bytes found", ['recv' => $parts[6], 'sent' => $parts[9]]);
                        }
                    }
                }
            }
            
            // Fallback: parse netstat -ib if we got no data
            if ($sent === 0 && $recv === 0) {
                Log::debug('macOS: Method 1 failed, trying netstat -ib fallback');
                $output = @shell_exec('netstat -ib 2>&1');
                if ($output) {
                    Log::debug('macOS netstat -ib raw output', ['output' => substr($output, 0, 1000)]);
                    foreach (explode("\n", $output) as $line) {
                        // Match en* interfaces with Link# network
                        if (preg_match('/^(en\d+)\s+\d+\s+<Link#/', $line)) {
                            Log::debug('macOS matched Link# line', ['line' => $line]);
                            $parts = preg_split('/\s+/', trim($line));
                            // Find numeric columns for bytes (usually columns 6 and 9)
                            $numericCols = [];
                            foreach ($parts as $idx => $val) {
                                if (is_numeric($val) && $val > 0) {
                                    $numericCols[] = ['idx' => $idx, 'val' => (int)$val];
                                }
                            }
                            Log::debug('macOS numeric columns found', ['numericCols' => $numericCols]);
                            // Typically: [mtu, ipkts, ierrs, ibytes, opkts, oerrs, obytes, coll]
                            // ibytes is usually the 4th numeric, obytes is 7th
                            if (count($numericCols) >= 7) {
                                $recv += $numericCols[3]['val'] ?? 0;
                                $sent += $numericCols[6]['val'] ?? 0;
                            }
                        }
                    }
                }
            }
            
            // Log final result
            Log::debug('macOS network stats final result', ['sent' => $sent, 'recv' => $recv]);
        } else {
            // Linux: Read from /proc/net/dev
            if (file_exists('/proc/net/dev')) {
                $content = file_get_contents('/proc/net/dev');
                $lines = explode("\n", $content);
                foreach ($lines as $line) {
                    // Skip loopback
                    if (strpos($line, 'lo:') !== false) continue;
                    if (preg_match('/^\s*\w+:\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)/', $line, $m)) {
                        $recv += (int) $m[1];
                        $sent += (int) $m[2];
                    }
                }
            }
        }
        
        return ['sent' => $sent, 'recv' => $recv];
    }

    /**
     * Get server uptime
     */
    protected function getUptime(): ?int
    {
        if (file_exists('/proc/uptime')) {
            $uptime = file_get_contents('/proc/uptime');
            return (int) explode(' ', $uptime)[0];
        }
        return null;
    }

    /**
     * Get public IP address (real external IP, not Docker internal)
     */
    protected function getPublicIp(): ?string
    {
        // Check cache first
        $cachedIp = cache()->get('agent_public_ip');
        if ($cachedIp) {
            return $cachedIp;
        }

        // Try multiple external IP services
        $services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com',
            'https://ipinfo.io/ip',
        ];

        foreach ($services as $service) {
            try {
                $response = Http::timeout(5)->get($service);
                if ($response->successful()) {
                    $ip = trim($response->body());
                    // Validate IP format
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        // Cache for 1 hour
                        cache()->put('agent_public_ip', $ip, now()->addHour());
                        return $ip;
                    }
                }
            } catch (\Exception $e) {
                continue;
            }
        }

        // Fallback to local IP if all external services fail
        $ip = gethostbyname(gethostname());
        if ($ip && $ip !== gethostname()) {
            return $ip;
        }

        return '0.0.0.0';
    }

    /**
     * Get CA certificate path for Windows SSL verification
     */
    protected function getCaCertPath(): ?string
    {
        // Check common locations for cacert.pem on Windows
        $possiblePaths = [];
        
        // Get PHP directory
        $phpBinary = PHP_BINARY;
        if ($phpBinary) {
            $phpDir = dirname($phpBinary);
            $possiblePaths[] = $phpDir . '\\cacert.pem';
            $possiblePaths[] = $phpDir . '\\extras\\ssl\\cacert.pem';
        }
        
        // Check common PHP installation locations
        $possiblePaths = array_merge($possiblePaths, [
            'C:\\tools\\php85\\cacert.pem',
            'C:\\tools\\php\\cacert.pem',
            'C:\\php\\cacert.pem',
            'C:\\xampp\\php\\extras\\ssl\\cacert.pem',
            'C:\\xampp-new\\php\\extras\\ssl\\cacert.pem',
            'C:\\Program Files\\PHP\\cacert.pem',
            'C:\\ProgramData\\ComposerSetup\\bin\\cacert.pem',
        ]);
        
        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                Log::debug('Found CA certificate at: ' . $path);
                return $path;
            }
        }
        
        // If not found, try to download it
        $downloadPath = sys_get_temp_dir() . '\\cacert.pem';
        if (!file_exists($downloadPath)) {
            try {
                // Download from curl.se (using file_get_contents with SSL disabled for bootstrap)
                $context = stream_context_create([
                    'ssl' => [
                        'verify_peer' => false,
                        'verify_peer_name' => false,
                    ],
                ]);
                $cacert = @file_get_contents('https://curl.se/ca/cacert.pem', false, $context);
                if ($cacert) {
                    file_put_contents($downloadPath, $cacert);
                    Log::info('Downloaded CA certificate to: ' . $downloadPath);
                    return $downloadPath;
                }
            } catch (\Exception $e) {
                Log::warning('Failed to download CA certificate: ' . $e->getMessage());
            }
        } elseif (file_exists($downloadPath)) {
            return $downloadPath;
        }
        
        return null;
    }

    /**
     * Sync alert to WAF Hub
     *
     * @param array $alertData
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncAlert(array $alertData): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for alerts');
            return null;
        }

        try {
            $response = $this->getHttpClient(10)
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/alerts", [
                    'agent_id' => $this->getAgentId(),
                    'alert' => $alertData,
                ]);

            if ($response->successful()) {
                Log::info('Alert synced to WAF Hub', [
                    'ip' => $alertData['source_ip'] ?? 'unknown',
                    'severity' => $alertData['severity'] ?? 'unknown',
                ]);
            } else {
                Log::error('WAF Hub rejected alert', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync alert to WAF Hub', [
                'error' => $e->getMessage(),
                'ip' => $alertData['source_ip'] ?? 'unknown',
            ]);
            return null;
        }
    }

    /**
     * Get agent ID from config or cache
     */
    private function getAgentId(): ?int
    {
        // Try to get from environment first
        if ($agentId = env('IDS_AGENT_ID')) {
            return (int) $agentId;
        }

        // Or from cache (set during registration)
        return cache('ids_agent_id');
    }

    /**
     * Check if WAF sync is properly configured
     */
    private function isConfigured(): bool
    {
        return !empty($this->agentToken) && !empty($this->wafUrl);
    }

    /**
     * Sync blocked IP to WAF Hub
     *
     * @param array $blockData
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncBlockedIP(array $blockData): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for blocking');
            return null;
        }

        try {
            $response = $this->getHttpClient(10)
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/block-ip", [
                    'agent_id' => $this->getAgentId(),
                    'block' => $blockData,
                ]);

            if ($response->successful()) {
                Log::info('Blocked IP synced to WAF Hub', [
                    'ip' => $blockData['ip'] ?? 'unknown',
                ]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync blocked IP', [
                'error' => $e->getMessage(),
                'ip' => $blockData['ip'] ?? 'unknown',
            ]);
            return null;
        }
    }

    /**
     * Sync IP unblock to WAF Hub
     *
     * @param string $ip
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncUnblockIP(string $ip): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for unblocking');
            return null;
        }

        try {
            $response = $this->getHttpClient(10)
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/unblock-ip", [
                    'agent_id' => $this->getAgentId(),
                    'ip' => $ip,
                ]);

            if ($response->successful()) {
                Log::info('Unblocked IP synced to WAF Hub', ['ip' => $ip]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync IP unblock', [
                'error' => $e->getMessage(),
                'ip' => $ip,
            ]);
            return null;
        }
    }

    /**
     * Fetch agent configuration from WAF Hub
     */
    public function fetchAgentConfig(): ?array
    {
        if (!$this->isConfigured()) {
            return null;
        }

        try {
            $response = $this->getHttpClient(10)
                ->withToken($this->agentToken)
                ->get("{$this->wafUrl}/api/ids/agents/config");

            if ($response->successful()) {
                $config = $response->json()['config'] ?? [];
                // Cache for 1 hour
                cache()->put('waf_agent_config', $config, now()->addHour());
                Log::info('Agent configuration fetched and cached from WAF Hub');
                return $config;
            }

            Log::warning('Failed to fetch agent config', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return null;
        } catch (\Exception $e) {
            Log::error('Exception during agent config fetch: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get cached agent configuration
     */
    public function getCachedConfig(): array
    {
        return cache()->get('waf_agent_config') ?? $this->fetchAgentConfig() ?? [];
    }

    /**
     * Detect the current platform
     */
    private function detectPlatform(): string
    {
        // Check if running in Docker (likely server deployment)
        if (file_exists('/.dockerenv') || file_exists('/run/.containerenv')) {
            return 'server';
        }
        
        if (stripos(PHP_OS, 'WIN') === 0) {
            return 'windows';
        } elseif (stripos(PHP_OS, 'Darwin') !== false) {
            return 'macos';
        }
        
        // Linux (desktop and server unified as 'linux')
        return 'linux';
    }
    
    /**
     * Regenerate the Windows sync service script with latest template
     */
    private function regenerateWindowsSyncScript(string $installDir): void
    {
        try {
            $dataDir = 'C:\ProgramData\SecurityOneIDS';
            $logDir = $dataDir . '\logs';
            
            // Ensure log directory exists
            if (!is_dir($logDir)) {
                mkdir($logDir, 0755, true);
            }
            
            // Create the simplified sync service script
            $script = <<<'POWERSHELL'
$ErrorActionPreference = 'Continue'

# Configuration
$InstallDir = 'INSTALL_DIR_PLACEHOLDER'
$LogDir = 'DATA_DIR_PLACEHOLDER\logs'
$LogFile = "$LogDir\watchdog.log"
$MaxFailures = 10
$FailCount = 0

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Find PHP path
$PhpPath = 'php'
$PossiblePaths = @(
    'C:\php\php.exe',
    'C:\tools\php\php.exe',
    'C:\Program Files\PHP\php.exe',
    'C:\xampp\php\php.exe',
    'C:\xampp-new\php\php.exe'
)
foreach ($p in $PossiblePaths) {
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        $PhpPath = $p
        break
    }
}

function Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Msg"
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    
    # Rotate if > 5MB
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile -EA SilentlyContinue).Length -gt 5MB)) {
        Move-Item $LogFile "$LogFile.old" -Force -EA SilentlyContinue
    }
}

Log "=== Sync Watchdog v3.0 Starting ===" 'INFO'
Log "Install Dir: $InstallDir" 'INFO'
Log "PHP Path: $PhpPath" 'INFO'

# Main loop - run waf:sync every 60 seconds
while ($true) {
    try {
        Set-Location $InstallDir
        
        # Run sync command with timeout (6 min max for concurrent tasks)
        $proc = Start-Process -FilePath $PhpPath -ArgumentList 'artisan','waf:sync' -WorkingDirectory $InstallDir -NoNewWindow -PassThru -Wait:$false
        $exited = $proc.WaitForExit(360000)  # 6 min timeout
        
        if (-not $exited) {
            Log "waf:sync timeout - killing process" 'WARN'
            $proc.Kill()
            $FailCount++
        } elseif ($proc.ExitCode -ne 0) {
            Log "waf:sync failed with code $($proc.ExitCode)" 'ERROR'
            $FailCount++
        } else {
            Log "waf:sync completed successfully" 'INFO'
            $FailCount = 0
        }
        
        # Full reset after too many failures
        if ($FailCount -ge $MaxFailures) {
            Log "Too many failures ($FailCount), performing full reset..." 'WARN'
            
            # Clear Laravel cache
            & $PhpPath artisan cache:clear 2>&1 | Out-Null
            & $PhpPath artisan config:clear 2>&1 | Out-Null
            
            $FailCount = 0
            Log "Reset complete, waiting 60s..." 'INFO'
            Start-Sleep -Seconds 60
        }
        
    } catch {
        Log "Exception: $($_.Exception.Message)" 'ERROR'
        $FailCount++
    }
    
    # Wait before next sync
    Start-Sleep -Seconds 60
}
POWERSHELL;

            // Replace placeholders
            $script = str_replace('INSTALL_DIR_PLACEHOLDER', $installDir, $script);
            $script = str_replace('DATA_DIR_PLACEHOLDER', $dataDir, $script);
            
            // Write the script
            $scriptPath = $installDir . '\run-sync-service.ps1';
            file_put_contents($scriptPath, $script);
            
            Log::info('Windows sync script regenerated', ['path' => $scriptPath]);
            
        } catch (\Exception $e) {
            Log::error('Failed to regenerate Windows sync script: ' . $e->getMessage());
        }
    }
}
