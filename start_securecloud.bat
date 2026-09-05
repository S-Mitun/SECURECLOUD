@echo off
setlocal enabledelayedexpansion
title SecureCloud 2.0 - Launcher

echo ======================================================================
echo           SECURECLOUD 2.0 - AUTOMATED ML THREAT PLATFORM
echo                    "Secure Storage. Intelligent Protection."
echo ======================================================================
echo.

:: 1. Check Python Existence
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not found in PATH!
    echo Please install Python 3.10+ and add it to your system PATH.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version') do set PYTHON_VER=%%v
echo [1/5] Verified Python: %PYTHON_VER%

:: 2. Initialize Database & Directory Structure
echo [2/5] Initializing Database, Vault Storage, and ML Models...
python scripts\init_db.py
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Database initialization failed.
    pause
    exit /b 1
)

:: 3. Launch SecureCloud Unified Server (Port 8000)
echo [3/4] Starting SecureCloud 2.0 Unified Server (http://127.0.0.1:8000)...
start "SecureCloud 2.0 Server" cmd /k "python backend\run.py"

:: 4. Health Check Polling before Browser Launch
echo [4/4] Polling Backend Health Check (http://127.0.0.1:8000/health)...
set /a attempts=0
:health_loop
set /a attempts+=1
timeout /t 1 /nobreak >nul
powershell -Command "try { $res = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/health' -TimeoutSec 2; if ($res.status -eq 'healthy' -or $res.status -eq 'HEALTHY') { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] SecureCloud 2.0 Unified Service is ONLINE and HEALTHY!
    goto launch_browser
)
if %attempts% GEQ 20 (
    echo [WARNING] Startup timed out. Opening browser anyway...
    goto launch_browser
)
echo       Waiting for service startup (Attempt %attempts%/20)...
goto health_loop

:launch_browser
echo.
echo ======================================================================
echo                 SECURECLOUD 2.0 IS RUNNING (ALL-IN-ONE)
echo ======================================================================
echo   Unified Application Web Link : http://127.0.0.1:8000
echo   Interactive API Swagger Docs : http://127.0.0.1:8000/docs
echo   Health Status Check Endpoint : http://127.0.0.1:8000/health
echo   Prometheus Telemetry Metrics : http://127.0.0.1:8000/metrics
echo ----------------------------------------------------------------------
echo   Default Admin : admin@securecloud.com   / AdminPass123!
echo   Default User  : analyst@securecloud.com / UserPass123!
echo ======================================================================
echo.
echo Opening SecureCloud 2.0 in default web browser...
start http://127.0.0.1:8000

echo Application is running. Close server window or run stop_securecloud.bat to shutdown.
pause

