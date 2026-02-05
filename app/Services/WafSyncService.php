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
                    'version' => config('app.version', '1.0.0'),
                    'version_updated_at' => $this->getLastGitPullTime(),
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
            echo "🔴 REBOOT SIGNAL DETECTED in config!\n";
            Log::warning('Reboot signal received from WAF Hub, initiating system restart...');
            $this->handleSystemReboot();
        } else {
            // Debug: show what addons we received
            $rebootValue = $config['addons']['reboot'] ?? 'NOT SET';
            echo "📋 Addons reboot value: " . json_encode($rebootValue) . "\n";
        }
        
        // DEBUG: Log all addons to sync.log
        $syncLogFile = PHP_OS_FAMILY === 'Windows' 
            ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\sync.log'
            : base_path('storage/logs/sync.log');
        $timestamp = date('Y-m-d H:i:s');
        $addonsJson = json_encode($config['addons'] ?? []);
        file_put_contents($syncLogFile, "[{$timestamp}] Received addons: {$addonsJson}\n", FILE_APPEND);
        
        // Handle lock signal from WAF Hub
        $lockValue = $config['addons']['lock'] ?? false;
        file_put_contents($syncLogFile, "[{$timestamp}] Lock value: " . json_encode($lockValue) . "\n", FILE_APPEND);
        
        if (!empty($config['addons']['lock'])) {
            echo "🔒 LOCK SIGNAL DETECTED in config!\n";
            file_put_contents($syncLogFile, "[{$timestamp}] LOCK TRIGGERED!\n", FILE_APPEND);
            Log::warning('Lock signal received from WAF Hub, locking system...');
            $this->handleSystemLock();
        }
        
        // Handle unlock signal from WAF Hub
        if (!empty($config['addons']['unlock'])) {
            echo "🔓 UNLOCK SIGNAL DETECTED in config!\n";
            Log::warning('Unlock signal received from WAF Hub, attempting to unlock...');
            $this->handleSystemUnlock();
        }
        
        // Handle disable login signal from WAF Hub
        if (!empty($config['addons']['disable_login'])) {
            echo "🚫 DISABLE LOGIN SIGNAL DETECTED in config!\n";
            Log::warning('Disable login signal received from WAF Hub, disabling password login...');
            $this->handleDisableLogin();
        }
        
        // Handle enable login signal from WAF Hub
        if (!empty($config['addons']['enable_login'])) {
            echo "✅ ENABLE LOGIN SIGNAL DETECTED in config!\n";
            Log::warning('Enable login signal received from WAF Hub, restoring password login...');
            $this->handleEnableLogin();
        }
        
        // Handle blocked IPs from WAF Hub
        if (!empty($config['blocked_ips'])) {
            $this->handleBlockedIps($config['blocked_ips']);
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
                exec('powershell -Command "Get-LocalUser | Where-Object {$_.Enabled -eq $false -and $_.Name -ne \'Guest\'} | Enable-LocalUser" 2>&1', $output, $returnCode);
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
            // Enhanced system metrics for WAF Hub display
            'cpu' => $this->getCpuUsage(),
            'memory' => $this->getMemoryUsage(),
            'disk' => $this->getDiskUsage(),
            'network' => $this->getNetworkUsage(),
        ];
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
        
        // Check if it's a desktop Linux vs server
        $isDesktop = getenv('DISPLAY') || getenv('WAYLAND_DISPLAY') || file_exists('/usr/share/xsessions');
        
        return $isDesktop ? 'desktop' : 'linux';
    }
}
