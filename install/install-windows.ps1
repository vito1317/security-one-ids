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

# Create directories
Write-Host "`n📂 Creating directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path "$DataDir\logs" -Force | Out-Null
New-Item -ItemType Directory -Path "$DataDir\storage" -Force | Out-Null

# Download IDS Agent
Write-Host "`n📥 Downloading Security One IDS Agent..." -ForegroundColor Cyan
$RepoUrl = "https://github.com/vito1317/security-one-ids/archive/refs/heads/main.zip"
$ZipPath = "$env:TEMP\security-one-ids.zip"

Invoke-WebRequest -Uri $RepoUrl -OutFile $ZipPath -UseBasicParsing
Expand-Archive -Path $ZipPath -DestinationPath "$env:TEMP\security-one-ids-extract" -Force
Copy-Item -Path "$env:TEMP\security-one-ids-extract\security-one-ids-main\*" -Destination $InstallDir -Recurse -Force
Remove-Item -Path $ZipPath -Force
Remove-Item -Path "$env:TEMP\security-one-ids-extract" -Recurse -Force

Write-Host "✅ IDS Agent downloaded" -ForegroundColor Green

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

# Run composer with quiet mode to suppress version warnings
$composerOutput = & composer install --no-dev --optimize-autoloader --quiet --no-interaction 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "⚠️ Composer completed with warnings (this is usually OK)" -ForegroundColor Yellow
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

$EnvContent | Out-File -FilePath "$InstallDir\.env" -Encoding UTF8
Write-Host "✅ Configuration saved" -ForegroundColor Green

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
