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
                    'system_info' => $this->getSystemInfo(),
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
     * Sync config received from WAF Hub
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
            'update_ids' => $config['addons']['update_ids'] ?? false,
            'update_definitions' => $config['addons']['update_definitions'] ?? false,
            'scan_now' => $config['addons']['scan_now'] ?? false,
            'scan_type' => $config['addons']['scan_type'] ?? 'quick',
        ]);
        
        // Handle ClamAV add-on
        if (!empty($config['addons']['clamav_enabled'])) {
            $this->handleClamavAddon();
        }
        
        // Handle IDS update signal
        if (!empty($config['addons']['update_ids'])) {
            $this->handleIdsUpdate();
        }
        
        // Handle virus definitions update signal
        if (!empty($config['addons']['update_definitions'])) {
            $this->handleDefinitionsUpdate();
        }
        
        // Handle scan now signal - run in background to not block heartbeat
        if (!empty($config['addons']['scan_now'])) {
            $scanType = $config['addons']['scan_type'] ?? 'quick';
            Log::info("Scan now signal received (type: {$scanType}), dispatching to background...");
            
            // Run scan in background process so it doesn't block heartbeat
            $basePath = base_path();
            $logPath = storage_path('logs/scan-output.log');
            $phpPath = PHP_BINARY ?: 'php';  // Use PHP_BINARY for correct PHP path
            
            // Platform-specific background execution
            if (PHP_OS_FAMILY === 'Darwin') {
                // macOS: Use pcntl_fork for truly detached process
                // Process::start() child dies when parent ends
                $phpPath = PHP_BINARY ?: '/opt/homebrew/bin/php';
                
                Log::info('Starting macOS async scan with fork', [
                    'php' => $phpPath,
                    'type' => $scanType,
                ]);
                
                if (function_exists('pcntl_fork')) {
                    $pid = pcntl_fork();
                    
                    if ($pid == -1) {
                        // Fork failed, fallback to direct exec
                        Log::error('pcntl_fork failed, running scan directly');
                        Artisan::call('ids:scan', ['--type' => $scanType]);
                    } elseif ($pid == 0) {
                        // Child process - run the scan
                        // Detach from parent's session
                        if (function_exists('posix_setsid')) {
                            posix_setsid();
                        }
                        
                        // Set PATH for homebrew
                        putenv('PATH=/opt/homebrew/bin:/usr/local/bin:' . getenv('PATH'));
                        
                        // Run the scan (this will block in child)
                        Artisan::call('ids:scan', ['--type' => $scanType]);
                        
                        // Exit child process when done
                        exit(0);
                    } else {
                        // Parent process - just continue
                        Log::info('Scan process forked', ['child_pid' => $pid]);
                        // Don't wait for child
                    }
                } else {
                    // pcntl not available - run in foreground as last resort
                    Log::warning('pcntl_fork not available, running scan in foreground');
                    Artisan::call('ids:scan', ['--type' => $scanType]);
                }
            } elseif (PHP_OS_FAMILY === 'Windows') {
                // Windows: Use PowerShell Start-Process for background execution
                $logPath = str_replace('/', '\\', $logPath);
                $basePath = str_replace('/', '\\', $basePath);
                
                // Build PowerShell command to run scan in background
                $command = "powershell -Command \"Start-Process -FilePath '{$phpPath}' -ArgumentList 'artisan','ids:scan','--type={$scanType}' -WorkingDirectory '{$basePath}' -WindowStyle Hidden -RedirectStandardOutput '{$logPath}'\"";
                
                Log::info('Executing Windows background scan command', ['command' => $command]);
                pclose(popen($command, 'r'));
                Log::info('Scan dispatched to background');
            } elseif (file_exists('/.dockerenv')) {
                // Docker: cd to container path for Laravel to work
                $command = "cd /var/www/html && nohup {$phpPath} artisan ids:scan --type={$scanType} >> /var/www/html/storage/logs/scan-output.log 2>&1 &";
                Log::info('Executing background scan command', ['command' => $command]);
                shell_exec($command);
                Log::info('Scan dispatched to background');
            } else {
                // Linux: cd to base path for Laravel to work
                $command = "cd {$basePath} && nohup {$phpPath} artisan ids:scan --type={$scanType} >> {$logPath} 2>&1 &";
                Log::info('Executing background scan command', ['command' => $command]);
                shell_exec($command);
                Log::info('Scan dispatched to background');
            }
        }
        
        // Handle reboot signal from WAF Hub
        if (!empty($config['addons']['reboot'])) {
            Log::warning('Reboot signal received from WAF Hub, initiating system restart...');
            $this->handleSystemReboot();
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
            Log::warning('System reboot initiated by WAF Hub remote command');
            
            // Small delay to allow log to be written
            sleep(2);
            
            if (PHP_OS_FAMILY === 'Windows') {
                // Windows: Use shutdown command with 5 second delay
                // /r = restart, /t 5 = 5 second timeout, /f = force apps to close
                Log::info('Executing Windows restart command...');
                pclose(popen('shutdown /r /t 5 /f /c "Security One IDS Agent: Reboot requested by WAF Hub"', 'r'));
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                // macOS: Use osascript or sudo shutdown
                Log::info('Executing macOS restart command...');
                exec('osascript -e \'tell app "System Events" to restart\' 2>&1 || sudo shutdown -r +1 "Security One IDS reboot"');
            } else {
                // Linux: Use shutdown command
                Log::info('Executing Linux restart command...');
                exec('sudo shutdown -r +1 "Security One IDS Agent: Reboot requested by WAF Hub" 2>&1 &');
            }
            
            Log::info('Reboot command dispatched');
            
        } catch (\Exception $e) {
            Log::error('Failed to execute reboot: ' . $e->getMessage());
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
            
            // Run git pull to get latest code
            Log::info('Pulling latest code from git...', ['platform' => $isWindows ? 'windows' : 'unix']);
            
            if ($isWindows) {
                // Windows: Use cmd.exe for better output capturing
                // PowerShell sometimes doesn't capture git output correctly
                $gitResult = Process::path($installDir)
                    ->timeout(300)
                    ->run('cmd /c "git pull origin main 2>&1"');
                
                // Log both output and error for debugging
                Log::info('Git command completed', [
                    'output' => $gitResult->output(),
                    'error' => $gitResult->errorOutput(),
                    'exitCode' => $gitResult->exitCode(),
                ]);
            } else {
                $gitResult = Process::path($installDir)
                    ->timeout(300)
                    ->run('git pull origin main 2>&1');
            }
            
            if (!$gitResult->successful()) {
                $errorMsg = $gitResult->output() ?: $gitResult->errorOutput() ?: 'Unknown error (exit code: ' . $gitResult->exitCode() . ')';
                Log::error('Git pull failed: ' . $errorMsg);
                $this->reportUpdateStatus('error');
                return;
            }
            
            Log::info('Git pull successful', ['output' => $gitResult->output()]);
            
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
                Log::info('Windows update completed, no automatic restart required');
                // Note: Windows Agent typically runs as a scheduled task or service
                // The next heartbeat will pick up the new code
            }
            
            // Get new version from config
            $newVersion = config('ids.version') ?? '1.0.0';
            
            Log::info('IDS update completed successfully', ['new_version' => $newVersion]);
            
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
     * Get system information
     */
    protected function getSystemInfo(): array
    {
        return [
            'os' => PHP_OS,
            'php_version' => PHP_VERSION,
            'memory_usage' => memory_get_usage(true),
            'load_average' => function_exists('sys_getloadavg') ? sys_getloadavg() : [],
            'uptime' => $this->getUptime(),
        ];
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
        
        // Check if it's a desktop Linux vs server
        $isDesktop = getenv('DISPLAY') || getenv('WAYLAND_DISPLAY') || file_exists('/usr/share/xsessions');
        
        return $isDesktop ? 'desktop' : 'linux';
    }
}
