# Security One IDS - Windows 診斷腳本
# 請在管理員 PowerShell 中執行此腳本

Write-Host "`n=== Security One IDS 診斷報告 ===" -ForegroundColor Cyan
Write-Host "時間: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# 1. 檢查安裝目錄
$InstallDir = "C:\SecurityOneIDS"
Write-Host "1. 安裝目錄檢查:" -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Write-Host "   ✅ 安裝目錄存在: $InstallDir" -ForegroundColor Green
    
    # Check key files
    $keyFiles = @(".env", "artisan", "run-sync-service.ps1", "run-scan-service.ps1")
    foreach ($f in $keyFiles) {
        if (Test-Path "$InstallDir\$f") {
            Write-Host "   ✅ $f 存在" -ForegroundColor Green
        } else {
            Write-Host "   ❌ $f 不存在!" -ForegroundColor Red
        }
    }
} else {
    Write-Host "   ❌ 安裝目錄不存在!" -ForegroundColor Red
}

# 2. 檢查 Scheduled Tasks
Write-Host "`n2. 排程工作檢查:" -ForegroundColor Yellow
$tasks = @("SecurityOneIDS-Scan", "SecurityOneIDS-Sync")
foreach ($taskName in $tasks) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        $state = $task.State
        $lastRun = (Get-ScheduledTaskInfo -TaskName $taskName).LastRunTime
        $lastResult = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
        
        $stateColor = if ($state -eq "Running") { "Green" } elseif ($state -eq "Ready") { "Yellow" } else { "Red" }
        Write-Host "   $taskName:" -ForegroundColor White
        Write-Host "      狀態: $state" -ForegroundColor $stateColor
        Write-Host "      上次執行: $lastRun"
        Write-Host "      結果代碼: $lastResult (0=成功)"
    } else {
        Write-Host "   ❌ $taskName 不存在!" -ForegroundColor Red
    }
}

# 3. 檢查 PHP
Write-Host "`n3. PHP 檢查:" -ForegroundColor Yellow
$phpPath = Get-Command php -ErrorAction SilentlyContinue
if ($phpPath) {
    Write-Host "   ✅ PHP 路徑: $($phpPath.Source)" -ForegroundColor Green
    $phpVersion = & php -v 2>&1 | Select-Object -First 1
    Write-Host "   版本: $phpVersion"
} else {
    Write-Host "   ❌ PHP 未找到!" -ForegroundColor Red
}

# 4. 檢查日誌目錄
Write-Host "`n4. 日誌檢查:" -ForegroundColor Yellow
$logDirs = @(
    "C:\ProgramData\SecurityOneIDS\logs",
    "$InstallDir\storage\logs"
)
foreach ($logDir in $logDirs) {
    if (Test-Path $logDir) {
        Write-Host "   ✅ 日誌目錄存在: $logDir" -ForegroundColor Green
        $logs = Get-ChildItem $logDir -File 2>$null | Sort-Object LastWriteTime -Descending | Select-Object -First 5
        foreach ($log in $logs) {
            Write-Host "      - $($log.Name) ($('{0:N2}' -f ($log.Length/1KB)) KB, $($log.LastWriteTime))"
        }
    } else {
        Write-Host "   ⚠️ 日誌目錄不存在: $logDir" -ForegroundColor Yellow
        # Try to create it
        try {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            Write-Host "      已自動建立目錄" -ForegroundColor Green
        } catch {
            Write-Host "      無法建立目錄" -ForegroundColor Red
        }
    }
}

# 5. 測試 PHP artisan
Write-Host "`n5. Artisan 測試:" -ForegroundColor Yellow
if (Test-Path "$InstallDir\artisan") {
    Set-Location $InstallDir
    try {
        $result = & php artisan --version 2>&1
        Write-Host "   ✅ Artisan 回應: $result" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Artisan 執行失敗: $_" -ForegroundColor Red
    }
}

# 6. 測試 WAF Sync
Write-Host "`n6. WAF Sync 測試:" -ForegroundColor Yellow
if (Test-Path "$InstallDir\artisan") {
    Set-Location $InstallDir
    Write-Host "   正在測試 waf:sync..."
    try {
        $result = & php artisan waf:sync 2>&1
        Write-Host "   結果: $result" -ForegroundColor Cyan
    } catch {
        Write-Host "   ❌ waf:sync 執行失敗: $_" -ForegroundColor Red
    }
}

# 7. 檢查 .env 設定
Write-Host "`n7. 環境設定檢查:" -ForegroundColor Yellow
$envPath = "$InstallDir\.env"
if (Test-Path $envPath) {
    $envContent = Get-Content $envPath
    foreach ($line in $envContent) {
        if ($line -match "^WAF_URL=") {
            Write-Host "   WAF_URL: $($line -replace 'WAF_URL=', '')"
        }
        if ($line -match "^AGENT_TOKEN=") {
            $token = $line -replace 'AGENT_TOKEN=', ''
            Write-Host "   AGENT_TOKEN: $($token.Substring(0, [Math]::Min(10, $token.Length)))..."
        }
        if ($line -match "^AGENT_NAME=") {
            Write-Host "   AGENT_NAME: $($line -replace 'AGENT_NAME=', '')"
        }
    }
} else {
    Write-Host "   ❌ .env 檔案不存在!" -ForegroundColor Red
}

# 8. PHP 錯誤日誌
Write-Host "`n8. 最近錯誤:" -ForegroundColor Yellow
$laravelLog = "$InstallDir\storage\logs\laravel.log"
if (Test-Path $laravelLog) {
    Write-Host "   最後 10 行 Laravel 日誌:" -ForegroundColor Cyan
    Get-Content $laravelLog -Tail 10 | ForEach-Object { Write-Host "   $_" }
} else {
    Write-Host "   Laravel 日誌不存在"
}

Write-Host "`n=== 診斷完成 ===" -ForegroundColor Cyan
Write-Host "如有問題請截圖回報`n"
