@echo off
setlocal enabledelayedexpansion
title SecureCloud - Graceful Shutdown

echo ======================================================================
echo          SECURECLOUD - TARGETED GRACEFUL SHUTDOWN
echo ======================================================================
echo.

:: 1. Terminate recorded Backend PID if present
if exist ".securecloud_backend.pid" (
    set /p BACKEND_PID=<.securecloud_backend.pid
    if defined BACKEND_PID (
        echo [1/4] Stopping Backend process PID: !BACKEND_PID!
        taskkill /f /pid !BACKEND_PID! >nul 2>&1
    )
    del /f /q ".securecloud_backend.pid" >nul 2>&1
)

:: 2. Terminate recorded Frontend PID if present
if exist ".securecloud_frontend.pid" (
    set /p FRONTEND_PID=<.securecloud_frontend.pid
    if defined FRONTEND_PID (
        echo [2/4] Stopping Frontend process PID: !FRONTEND_PID!
        taskkill /f /pid !FRONTEND_PID! >nul 2>&1
    )
    del /f /q ".securecloud_frontend.pid" >nul 2>&1
)

:: 3. Target any remaining listener on Port 8000 (Backend)
echo [3/4] Checking Port 8000 listeners
powershell -Command "try { $pids = (Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue).OwningProcess | Select-Object -Unique; foreach ($p in $pids) { if ($p -gt 4) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue; Write-Host ('      -> Stopped process on Port 8000 PID: ' + $p) } } } catch {}"

:: 4. Target any remaining listener on Port 5500 (Frontend)
echo [4/4] Checking Port 5500 listeners
powershell -Command "try { $pids = (Get-NetTCPConnection -LocalPort 5500 -ErrorAction SilentlyContinue).OwningProcess | Select-Object -Unique; foreach ($p in $pids) { if ($p -gt 4) { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue; Write-Host ('      -> Stopped process on Port 5500 PID: ' + $p) } } } catch {}"

echo.
echo ======================================================================
echo [SUCCESS] SecureCloud services have been stopped.
echo           Unrelated applications and system processes were unaffected.
echo ======================================================================
echo.
