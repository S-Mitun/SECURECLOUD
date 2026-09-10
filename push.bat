@echo off
echo ===================================================
echo   SecureCloud - GitHub Push Utility
echo ===================================================
set "PATH=C:\Users\Mitun S\AppData\Local\Programs\Git\cmd;C:\Users\Mitun S\AppData\Local\Programs\Git\mingw64\bin;%PATH%"

where git >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Git could not be located at C:\Users\Mitun S\AppData\Local\Programs\Git\cmd
    pause
    exit /b 1
)

echo Pushing commit to https://github.com/S-Mitun/SECURECLOUD ...
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ===================================================
    echo   Push completed successfully!
    echo ===================================================
) else (
    echo.
    echo [NOTICE] If prompted by GitHub in a browser window, complete authentication and retry.
)
pause
