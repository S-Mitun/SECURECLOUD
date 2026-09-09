# SecureCloud 2.0 - Development Server Runner
# Launches unified service in development mode.

$ROOT_DIR = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ROOT_DIR

# Initialize environment
python scripts/init_db.py

# Start Unified Server
$serverProcess = Start-Process -FilePath "python" -ArgumentList "backend/run.py" -PassThru
$serverProcess.Id | Out-File -FilePath ".securecloud_backend.pid" -Force

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "SECURECLOUD 2.0 UNIFIED DEVELOPMENT SERVER" -ForegroundColor White
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Unified Application Web Link:" -ForegroundColor Yellow
Write-Host "http://127.0.0.1:8000" -ForegroundColor White
Write-Host ""
Write-Host "Interactive API Docs:" -ForegroundColor Yellow
Write-Host "http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host ""
Write-Host "Health Check:" -ForegroundColor Yellow
Write-Host "http://127.0.0.1:8000/health" -ForegroundColor White
Write-Host ""
Write-Host "Prometheus Telemetry:" -ForegroundColor Yellow
Write-Host "http://127.0.0.1:8000/metrics" -ForegroundColor White
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
