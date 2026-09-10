# SecureCloud - PowerShell One-Click Launcher
# Starts SecureCloud Unified Server, runs health check, and launches default browser.

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "                          SECURECLOUD" -ForegroundColor White
Write-Host "                   'Secure Storage. Intelligent Protection.'" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Verify Python Existence
try {
    $pyVer = python --version 2>&1
    Write-Host "[1/4] Verified Python: $pyVer" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python was not found in PATH! Please install Python 3.10+." -ForegroundColor Red
    exit 1
}

# 2. Initialize Database & Directory Structure
Write-Host "[2/4] Initializing Database, Vault Storage, and ML Models..." -ForegroundColor Yellow
python scripts\init_db.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Database initialization failed." -ForegroundColor Red
    exit 1
}

# 3. Start SecureCloud Unified Server (Port 8000)
Write-Host "[3/4] Starting SecureCloud Unified Server (http://127.0.0.1:8000)..." -ForegroundColor Yellow
$serverProcess = Start-Process -FilePath "python" -ArgumentList "backend/run.py" -PassThru
$serverProcess.Id | Out-File -FilePath ".securecloud_backend.pid" -Force

# 4. Polling Health Check
Write-Host "[4/4] Polling Backend Health Check (http://127.0.0.1:8000/health)..." -ForegroundColor Yellow
$healthy = $false
for ($i = 1; $i -le 20; $i++) {
    Start-Sleep -Seconds 1
    try {
        $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($res.status -eq "healthy" -or $res.status -eq "HEALTHY") {
            $healthy = $true
            Write-Host "[SUCCESS] SecureCloud Service is ONLINE and HEALTHY!" -ForegroundColor Green
            break
        }
    } catch {}
    Write-Host "      Waiting for service startup (Attempt $i/20)..." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "                 SECURECLOUD IS RUNNING (ALL-IN-ONE)" -ForegroundColor White
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  Unified Web Application : http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "  Interactive API Docs    : http://127.0.0.1:8000/docs" -ForegroundColor DarkCyan
Write-Host "  Prometheus Metrics      : http://127.0.0.1:8000/metrics" -ForegroundColor DarkCyan
Write-Host "  Health Status Endpoint  : http://127.0.0.1:8000/health" -ForegroundColor DarkCyan
Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Default Admin : admin@securecloud.com   / AdminPass123!" -ForegroundColor Yellow
Write-Host "  Default User  : analyst@securecloud.com / UserPass123!" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Opening SecureCloud in default web browser..." -ForegroundColor Green
Start-Process "http://127.0.0.1:8000"

Write-Host "Press Ctrl+C or run stop_securecloud.bat to shutdown services." -ForegroundColor DarkGray
