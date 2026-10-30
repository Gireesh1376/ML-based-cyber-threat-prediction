@echo off
setlocal

title AEGIS - Restarting Services
cd /d "%~dp0"

echo ===============================================================================
echo                AEGIS - Restarting All Platform Services
echo ===============================================================================
echo.

call "%~dp0stop_aegis.bat"

echo.
echo [INFO] Waiting 3 seconds for port release before relaunching...
ping -n 4 127.0.0.1 >nul 2>&1

call "%~dp0start_aegis.bat"
