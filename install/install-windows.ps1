# Security One IDS Agent - Windows Installation Script
# Run as Administrator in PowerShell:
# iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/vito1317/security-one-ids/main/install/install-windows.ps1'))

param(
    [string]$WafHubUrl = $env:WAF_HUB_URL,
    [string]$AgentToken = $env:AGENT_TOKEN,
    [string]$AgentName = $(if ($env:AGENT_NAME) { $env:AGENT_NAME } else { $env:COMPUTERNAME })
)

$ErrorActionPreference = "Stop"

Write-Host "
╔═══════════════════════════════════════════════════╗
║     Security One IDS Agent - Windows Installer    ║
╚═══════════════════════════════════════════════════╝
" -ForegroundColor Cyan

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ Please run this script as Administrator" -ForegroundColor Red
    exit 1
}

# Configuration
$InstallDir = "$env:ProgramFiles\SecurityOneIDS"
$DataDir = "$env:ProgramData\SecurityOneIDS"
$ServiceName = "SecurityOneIDS"

Write-Host "📁 Installation Directory: $InstallDir" -ForegroundColor Yellow
Write-Host "📁 Data Directory: $DataDir" -ForegroundColor Yellow

# Check prerequisites
Write-Host "`n🔍 Checking prerequisites..." -ForegroundColor Cyan

# Check PHP
$phpPath = Get-Command php -ErrorAction SilentlyContinue
if (-not $phpPath) {
    Write-Host "❌ PHP not found. Installing PHP..." -ForegroundColor Yellow
    
    # Download and install PHP using Chocolatey or manual download
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install php -y
    } else {
        Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        choco install php -y
    }
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

Write-Host "✅ PHP is installed" -ForegroundColor Green

# Enable required PHP extensions
Write-Host "🔧 Enabling required PHP extensions..." -ForegroundColor Cyan

# Find php.ini location
$phpIniPath = & php -i 2>$null | Select-String "Loaded Configuration File" | ForEach-Object { $_.ToString().Split("=>")[1].Trim() }
if (-not $phpIniPath -or $phpIniPath -eq "(none)") {
    # Try to find php.ini in common locations
    $phpDir = Split-Path (Get-Command php).Source -Parent
    $possiblePaths = @(
        "$phpDir\php.ini",
        "$phpDir\php.ini-development",
        "$phpDir\php.ini-production",
        "C:\php\php.ini",
        "C:\tools\php\php.ini",
        "C:\xampp\php\php.ini",
        "C:\xampp-new\php\php.ini"
    )
    
    foreach ($p in $possiblePaths) {
        if (Test-Path $p) {
            $phpIniPath = $p
            break
        }
    }
    
    # If still no php.ini, copy from sample
    if (-not $phpIniPath -or -not (Test-Path $phpIniPath)) {
        $sampleIni = Get-ChildItem -Path $phpDir -Filter "php.ini-*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sampleIni) {
            Copy-Item $sampleIni.FullName "$phpDir\php.ini"
            $phpIniPath = "$phpDir\php.ini"
            Write-Host "Created php.ini from sample" -ForegroundColor Yellow
        }
    }
}

if ($phpIniPath -and (Test-Path $phpIniPath)) {
    Write-Host "Found php.ini: $phpIniPath" -ForegroundColor Yellow
    
    # Extensions to enable
    $extensions = @("fileinfo", "curl", "mbstring", "openssl", "pdo_sqlite", "sqlite3")
    $content = Get-Content $phpIniPath -Raw
    $modified = $false
    
    foreach ($ext in $extensions) {
        # Check if extension is commented out
        if ($content -match ";\s*extension\s*=\s*$ext") {
            $content = $content -replace ";\s*extension\s*=\s*$ext", "extension=$ext"
            $modified = $true
            Write-Host "  ✅ Enabled extension: $ext" -ForegroundColor Green
        } elseif ($content -notmatch "extension\s*=\s*$ext") {
            # Extension not found, add it
            $content = $content + "`nextension=$ext"
            $modified = $true
            Write-Host "  ✅ Added extension: $ext" -ForegroundColor Green
        } else {
            Write-Host "  ✓ Extension already enabled: $ext" -ForegroundColor Gray
        }
    }
    
    if ($modified) {
        Set-Content $phpIniPath $content -Force
        Write-Host "✅ PHP extensions configured" -ForegroundColor Green
    }
} else {
    Write-Host "⚠️ Could not find php.ini - extensions may need manual configuration" -ForegroundColor Yellow
}

# Create directories
Write-Host "`n📂 Creating directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path "$DataDir\logs" -Force | Out-Null
New-Item -ItemType Directory -Path "$DataDir\storage" -Force | Out-Null

# Download IDS Agent via git clone (required for updates)
Write-Host "`n📥 Downloading Security One IDS Agent via Git...`n" -ForegroundColor Cyan

# Check if git is installed
$gitPath = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitPath) {
    Write-Host "Installing Git..." -ForegroundColor Yellow
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        & choco install git -y
    } elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        & winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
    } else {
        # Install chocolatey first, then git
        Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        & 'C:\ProgramData\chocolatey\bin\choco.exe' install git -y
    }
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}
Write-Host "✅ Git is installed" -ForegroundColor Green

# Clone or update repository
$RepoUrl = "https://github.com/vito1317/security-one-ids.git"

if (Test-Path "$InstallDir\.git") {
    Write-Host "📂 Existing git repository found, updating..." -ForegroundColor Yellow
    Set-Location $InstallDir
    & git fetch origin
    & git reset --hard origin/main
} else {
# Remove existing directory if it's not a git repo
    if (Test-Path $InstallDir) {
        # Stop any running scheduled tasks first
        Write-Host "🛑 Stopping existing services..." -ForegroundColor Yellow
        Stop-ScheduledTask -TaskName "SecurityOneIDS-Scan" -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName "SecurityOneIDS-Sync" -ErrorAction SilentlyContinue
        
        # Wait a moment for processes to terminate
        Start-Sleep -Seconds 2
        
        # Kill ALL PHP processes (more aggressive)
        Write-Host "🔪 Terminating PHP processes..." -ForegroundColor Yellow
        Get-Process -Name php -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process -Name php-cgi -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        
        # Wait for file handles to be released
        Start-Sleep -Seconds 3
        
        # Backup .env if exists
        $envBackup = $null
        if (Test-Path "$InstallDir\.env") {
            $envBackup = Get-Content "$InstallDir\.env" -Raw
        }
        
        # Try to remove directory with multiple attempts
        $maxAttempts = 3
        $attempt = 1
        while ($attempt -le $maxAttempts) {
            try {
                Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
                break
            } catch {
                Write-Host "⚠️ Attempt $attempt/$maxAttempts - Could not remove directory: $($_.Exception.Message)" -ForegroundColor Yellow
                if ($attempt -eq $maxAttempts) {
                    Write-Host "❌ Failed to remove directory. Please close any applications using files in $InstallDir and try again." -ForegroundColor Red
                    exit 1
                }
                $attempt++
                Start-Sleep -Seconds 5
            }
        }
    }
    
    # Clone the repository
    & git clone $RepoUrl $InstallDir
    
    # Restore .env if it was backed up
    if ($envBackup) {
        $envBackup | Out-File -FilePath "$InstallDir\.env" -Encoding UTF8
    }
}

Write-Host "✅ IDS Agent downloaded via Git" -ForegroundColor Green

# Install Composer dependencies
Write-Host "`n📦 Installing dependencies..." -ForegroundColor Cyan
Set-Location $InstallDir

# Check if composer is available
$composerPath = Get-Command composer -ErrorAction SilentlyContinue
if (-not $composerPath) {
    Write-Host "Installing Composer..." -ForegroundColor Yellow
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install composer -y
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    }
}

# Run composer with ignore-platform-reqs to bypass missing extensions like ext-fileinfo
Write-Host "Running composer install (this may take a moment)..." -ForegroundColor Yellow

# Remove old composer.lock as it may have dependencies requiring missing extensions
if (Test-Path "$InstallDir\composer.lock") {
    Remove-Item "$InstallDir\composer.lock" -Force
    Write-Host "Removed old composer.lock" -ForegroundColor Yellow
}

# Verify PHP has fileinfo enabled now
Write-Host "Verifying PHP extensions..." -ForegroundColor Yellow
$phpExtensions = & php -m 2>$null
if ($phpExtensions -contains 'fileinfo') {
    Write-Host "✅ PHP fileinfo extension is enabled" -ForegroundColor Green
} else {
    Write-Host "⚠️ PHP fileinfo extension not detected" -ForegroundColor Yellow
}

# Run composer update using Start-Process to avoid PowerShell stderr issues
Write-Host "Running composer update..." -ForegroundColor Yellow

# Suppress all errors from composer (it writes progress to stderr)
$ErrorActionPreference = 'SilentlyContinue'

# Find composer.phar or use composer command
$composerPhar = "C:\ProgramData\ComposerSetup\bin\composer.phar"
if (-not (Test-Path $composerPhar)) {
    $composerPhar = "C:\Program Files (x86)\ComposerSetup\bin\composer.phar"
}

if (Test-Path $composerPhar) {
    Write-Host "Using composer.phar directly..." -ForegroundColor Yellow
    $process = Start-Process -FilePath "php" -ArgumentList "$composerPhar update --no-dev --optimize-autoloader --no-interaction --ignore-platform-reqs" -WorkingDirectory $InstallDir -Wait -NoNewWindow -PassThru
} else {
    Write-Host "Using composer command..." -ForegroundColor Yellow
    $process = Start-Process -FilePath "composer" -ArgumentList "update --no-dev --optimize-autoloader --no-interaction --ignore-platform-reqs" -WorkingDirectory $InstallDir -Wait -NoNewWindow -PassThru
}

$ErrorActionPreference = 'Continue'

if ($process.ExitCode -eq 0) {
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "⚠️ First attempt had issues (exit code: $($process.ExitCode)), trying install..." -ForegroundColor Yellow
    $ErrorActionPreference = 'SilentlyContinue'
    $process2 = Start-Process -FilePath "composer" -ArgumentList "install --no-dev --no-interaction --ignore-platform-reqs" -WorkingDirectory $InstallDir -Wait -NoNewWindow -PassThru
    $ErrorActionPreference = 'Continue'
    
    if ($process2.ExitCode -eq 0) {
        Write-Host "✅ Dependencies installed (fallback)" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Composer had warnings but may have succeeded. Continuing..." -ForegroundColor Yellow
    }
}

# Configure environment
Write-Host "`n⚙️ Configuring IDS Agent..." -ForegroundColor Cyan

# Check for existing configuration
$ExistingEnvPath = "$InstallDir\.env"
if ((Test-Path $ExistingEnvPath) -and (-not $WafHubUrl) -and (-not $AgentToken)) {
    Write-Host "📋 Found existing configuration, loading previous settings..." -ForegroundColor Yellow
    
    $EnvFileContent = Get-Content $ExistingEnvPath
    
    # Parse existing values
    foreach ($line in $EnvFileContent) {
        if ($line -match '^WAF_URL="(.+)"') {
            $ExistingWafUrl = $matches[1]
        }
        if ($line -match '^AGENT_TOKEN="(.+)"') {
            $ExistingToken = $matches[1]
        }
        if ($line -match '^AGENT_NAME="(.+)"') {
            $ExistingName = $matches[1]
        }
    }
    
    # Use existing values if found
    if ($ExistingWafUrl) {
        $WafHubUrl = $ExistingWafUrl
        Write-Host "  WAF Hub URL: $WafHubUrl" -ForegroundColor Green
    }
    
    if ($ExistingToken) {
        $AgentToken = $ExistingToken
        Write-Host "  Agent Token: (using existing token)" -ForegroundColor Green
    }
    
    if ($ExistingName) {
        $AgentName = $ExistingName
        Write-Host "  Agent Name: $AgentName" -ForegroundColor Green
    }
    
    Write-Host "✅ Using existing configuration" -ForegroundColor Green
}

# Get configuration if still not provided
if (-not $WafHubUrl) {
    $WafHubUrl = Read-Host "Enter WAF Hub URL (e.g., https://waf.example.com)"
}
if (-not $AgentToken) {
    $AgentToken = Read-Host "Enter Agent Token"
}

$EnvContent = @"
APP_NAME="Security One IDS"
APP_ENV=production
APP_DEBUG=false

WAF_URL="$WafHubUrl"
AGENT_TOKEN="$AgentToken"
AGENT_NAME="$AgentName"

OLLAMA_URL=https://ollama.futron-life.com
OLLAMA_MODEL=sentinel-security
AI_DETECTION_ENABLED=true
AI_TIMEOUT=30

LOG_CHANNEL=daily
LOG_LEVEL=info
"@

# Write .env file with UTF8 encoding WITHOUT BOM (important for Laravel)
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText("$InstallDir\.env", $EnvContent, $Utf8NoBom)
Write-Host "✅ Configuration saved (UTF8 no BOM)" -ForegroundColor Green

# Create SQLite database and run migrations
Write-Host "`n🗄️  Setting up database...`n" -ForegroundColor Cyan

# Create all required directories
$RequiredDirs = @(
    "$InstallDir\database",
    "$InstallDir\storage\logs",
    "$InstallDir\storage\framework\sessions",
    "$InstallDir\storage\framework\views",
    "$InstallDir\storage\framework\cache",
    "$InstallDir\bootstrap\cache"
)

foreach ($dir in $RequiredDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Create database file
$DbPath = "$InstallDir\database\database.sqlite"
if (-not (Test-Path $DbPath)) {
    New-Item -ItemType File -Path $DbPath -Force | Out-Null
}

# Set permissions (allow full control for SYSTEM and Administrators)
Write-Host "🔐 Setting permissions..." -ForegroundColor Cyan
$Acl = Get-Acl $InstallDir
$Permission = "NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
$Acl.SetAccessRule($AccessRule)
Set-Acl $InstallDir $Acl

# Set storage directory permissions
$StorageDirs = @("$InstallDir\storage", "$InstallDir\database", "$InstallDir\bootstrap\cache", "$DataDir\logs")
foreach ($dir in $StorageDirs) {
    if (Test-Path $dir) {
        $Acl = Get-Acl $dir
        $Permission = "Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow"
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
        $Acl.SetAccessRule($AccessRule)
        Set-Acl $dir $Acl
    }
}
Write-Host "✅ Permissions set" -ForegroundColor Green

# Run migrations
Set-Location $InstallDir
& php artisan migrate --force 2>$null
& php artisan package:discover --ansi 2>$null
Write-Host "✅ Database ready" -ForegroundColor Green

# Create Windows Service
Write-Host "`n🔧 Creating Windows Services..." -ForegroundColor Cyan

# Create scan service script (runs every 5 minutes)
$ScanServiceScript = @"
`$ErrorActionPreference = 'Continue'
Set-Location '$InstallDir'
while (`$true) {
    php artisan desktop:scan --full 2>&1 | Out-File -FilePath '$DataDir\logs\scan.log' -Append
    Start-Sleep -Seconds 300
}
"@

$ScanServiceScript | Out-File -FilePath "$InstallDir\run-scan-service.ps1" -Encoding UTF8

# Create sync service script (runs every minute for heartbeat)
$SyncServiceScript = @"
`$ErrorActionPreference = 'Continue'
Set-Location '$InstallDir'
while (`$true) {
    php artisan waf:sync 2>&1 | Out-File -FilePath '$DataDir\logs\sync.log' -Append
    Start-Sleep -Seconds 60
}
"@

$SyncServiceScript | Out-File -FilePath "$InstallDir\run-sync-service.ps1" -Encoding UTF8

# Register scan scheduled task (for desktop:scan)
$ScanTaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\run-scan-service.ps1`""
$ScanTaskTrigger = New-ScheduledTaskTrigger -AtStartup
$ScanTaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$ScanTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "$ServiceName-Scan" -Action $ScanTaskAction -Trigger $ScanTaskTrigger -Principal $ScanTaskPrincipal -Settings $ScanTaskSettings -Force | Out-Null
Write-Host "✅ Scan Service created ($ServiceName-Scan)" -ForegroundColor Green

# Register sync scheduled task (for waf:sync heartbeat)
$SyncTaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\run-sync-service.ps1`""
$SyncTaskTrigger = New-ScheduledTaskTrigger -AtStartup
$SyncTaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$SyncTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "$ServiceName-Sync" -Action $SyncTaskAction -Trigger $SyncTaskTrigger -Principal $SyncTaskPrincipal -Settings $SyncTaskSettings -Force | Out-Null
Write-Host "✅ Sync Service created ($ServiceName-Sync)" -ForegroundColor Green

# Start services
Write-Host "`n🚀 Starting IDS Agent..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName "$ServiceName-Scan" -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "$ServiceName-Sync" -ErrorAction SilentlyContinue

# Register with WAF Hub
Write-Host "`n📡 Registering with WAF Hub..." -ForegroundColor Cyan
Set-Location $InstallDir
& php artisan waf:sync --register

# Run initial scan
Write-Host "`n🔍 Running initial security scan..." -ForegroundColor Cyan
& php artisan desktop:scan

Write-Host "`n
╔═══════════════════════════════════════════════════╗
║      ✅ Installation Complete!                     ║
╠═══════════════════════════════════════════════════╣
║  Install Path: $InstallDir
║  Data Path:    $DataDir
║  Services:     $ServiceName-Scan (Scheduled Task)
║                $ServiceName-Sync (Heartbeat)
║                                                   
║  Commands:                                        
║    Manual Scan:  php artisan desktop:scan        
║    Full Scan:    php artisan desktop:scan --full 
║    Manual Sync:  php artisan waf:sync
║    Check Status: Get-ScheduledTask $ServiceName*
║                                                   
╚═══════════════════════════════════════════════════╝
" -ForegroundColor Green
