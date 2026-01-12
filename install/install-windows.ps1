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
Write-Host "`n🗄️  Setting up database..." -ForegroundColor Cyan
$DbPath = "$InstallDir\database\database.sqlite"
if (-not (Test-Path $DbPath)) {
    New-Item -ItemType File -Path $DbPath -Force | Out-Null
}
Set-Location $InstallDir
& php artisan migrate --force 2>$null
& php artisan package:discover --ansi 2>$null
Write-Host "✅ Database ready" -ForegroundColor Green

# Create Windows Service
Write-Host "`n🔧 Creating Windows Service..." -ForegroundColor Cyan

$ServiceScript = @"
`$ErrorActionPreference = 'Continue'
Set-Location '$InstallDir'
while (`$true) {
    php artisan desktop:scan --full 2>&1 | Out-File -FilePath '$DataDir\logs\scan.log' -Append
    Start-Sleep -Seconds 300
}
"@

$ServiceScript | Out-File -FilePath "$InstallDir\run-service.ps1" -Encoding UTF8

# Register scheduled task as service alternative
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\run-service.ps1`""
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $ServiceName -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Settings $TaskSettings -Force | Out-Null
Write-Host "✅ Windows Service created" -ForegroundColor Green

# Start service
Write-Host "`n🚀 Starting IDS Agent..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName $ServiceName

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
║  Service:      $ServiceName (Scheduled Task)
║                                                   
║  Commands:                                        
║    Manual Scan:  php artisan desktop:scan        
║    Full Scan:    php artisan desktop:scan --full 
║    Check Status: Get-ScheduledTask $ServiceName
║                                                   
╚═══════════════════════════════════════════════════╝
" -ForegroundColor Green
