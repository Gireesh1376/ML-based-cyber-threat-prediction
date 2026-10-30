@echo off
setlocal EnableDelayedExpansion

title AEGIS - Service Shutdown
cd /d "%~dp0"

echo ===============================================================================
echo                AEGIS - Cybersecurity Operations Platform Shutdown
echo ===============================================================================
echo.

:: 1. Terminate Verified AEGIS Frontend (port 5173)
echo [INFO] Inspecting Frontend processes (port 5173)...
set "FRONTEND_KILLED="
set "P5173_PID="
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":5173\>" ^| findstr "LISTENING" 2^>nul') do (
    set "P5173_PID=%%a"
)

set "TRACKED_F_PID="
if exist "%~dp0.aegis_frontend.pid" set /p TRACKED_F_PID=<"%~dp0.aegis_frontend.pid"

if defined P5173_PID (
    set "IS_AEGIS_FE="
    if defined TRACKED_F_PID if "!TRACKED_F_PID!"=="!P5173_PID!" set "IS_AEGIS_FE=1"
    
    if not defined IS_AEGIS_FE (
        curl.exe -s --connect-timeout 2 http://localhost:5173 > "%~dp0.fe_stop_chk.tmp" 2>nul
        findstr /i "Cyber Threat Prediction" "%~dp0.fe_stop_chk.tmp" >nul 2>&1
        if !ERRORLEVEL! equ 0 set "IS_AEGIS_FE=1"
        findstr /i "main.tsx" "%~dp0.fe_stop_chk.tmp" >nul 2>&1
        if !ERRORLEVEL! equ 0 set "IS_AEGIS_FE=1"
        if exist "%~dp0.fe_stop_chk.tmp" del "%~dp0.fe_stop_chk.tmp" >nul 2>&1
    )
    
    if defined IS_AEGIS_FE (
        echo [INFO] Stopping verified AEGIS Frontend process [PID: !P5173_PID!]...
        taskkill /T /F /PID !P5173_PID! >nul 2>&1
        echo [OK] AEGIS Frontend process stopped safely.
        set "FRONTEND_KILLED=1"
    ) else (
        echo [WARN] Process on port 5173 [PID: !P5173_PID!] cannot be verified as AEGIS Frontend.
        echo [INFO] Preserving unrelated application on port 5173. It was NOT terminated.
    )
) else (
    echo [INFO] No process listening on port 5173.
)

:: Terminate tracked PID if distinct and active
if defined TRACKED_F_PID (
    tasklist /FI "PID eq !TRACKED_F_PID!" 2>nul | findstr "!TRACKED_F_PID!" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        if not defined FRONTEND_KILLED (
            taskkill /T /F /PID !TRACKED_F_PID! >nul 2>&1
            echo [OK] Stopped tracked AEGIS Frontend process [PID: !TRACKED_F_PID!].
        )
    )
    if exist "%~dp0.aegis_frontend.pid" del "%~dp0.aegis_frontend.pid" >nul 2>&1
)
taskkill /FI "WINDOWTITLE eq AEGIS Frontend*" /T /F >nul 2>&1
echo.

:: 2. Terminate Verified AEGIS Backend (port 8000)
echo [INFO] Inspecting Backend processes (port 8000)...
set "BACKEND_KILLED="
set "P8000_PID="
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":8000\>" ^| findstr "LISTENING" 2^>nul') do (
    set "P8000_PID=%%a"
)

set "TRACKED_B_PID="
if exist "%~dp0.aegis_backend.pid" set /p TRACKED_B_PID=<"%~dp0.aegis_backend.pid"

if defined P8000_PID (
    set "IS_AEGIS_BE="
    if defined TRACKED_B_PID if "!TRACKED_B_PID!"=="!P8000_PID!" set "IS_AEGIS_BE=1"
    
    if not defined IS_AEGIS_BE (
        curl.exe -s --connect-timeout 2 http://127.0.0.1:8000/api/health > "%~dp0.be_stop_chk.tmp" 2>nul
        findstr /i "cyber-threat-prediction" "%~dp0.be_stop_chk.tmp" >nul 2>&1
        if !ERRORLEVEL! equ 0 set "IS_AEGIS_BE=1"
        if exist "%~dp0.be_stop_chk.tmp" del "%~dp0.be_stop_chk.tmp" >nul 2>&1
    )
    
    if defined IS_AEGIS_BE (
        echo [INFO] Stopping verified AEGIS Backend process [PID: !P8000_PID!]...
        taskkill /T /F /PID !P8000_PID! >nul 2>&1
        echo [OK] AEGIS Backend process stopped safely.
        set "BACKEND_KILLED=1"
    ) else (
        echo [WARN] Process on port 8000 [PID: !P8000_PID!] cannot be verified as AEGIS Backend.
        echo [INFO] Preserving unrelated application on port 8000. It was NOT terminated.
    )
) else (
    echo [INFO] No process listening on port 8000.
)

:: Terminate tracked PID if distinct and active
if defined TRACKED_B_PID (
    tasklist /FI "PID eq !TRACKED_B_PID!" 2>nul | findstr "!TRACKED_B_PID!" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        if not defined BACKEND_KILLED (
            taskkill /T /F /PID !TRACKED_B_PID! >nul 2>&1
            echo [OK] Stopped tracked AEGIS Backend process [PID: !TRACKED_B_PID!].
        )
    )
    if exist "%~dp0.aegis_backend.pid" del "%~dp0.aegis_backend.pid" >nul 2>&1
)
taskkill /FI "WINDOWTITLE eq AEGIS Backend*" /T /F >nul 2>&1
echo.

:: 3. Stop Elasticsearch Docker container safely without deleting volumes or user data
echo [INFO] Inspecting Docker container state...
docker info >nul 2>&1
if !ERRORLEVEL! neq 0 (
    echo [INFO] Docker daemon is not running. No containers to stop.
    goto CLEANUP_DONE
)

docker ps --filter "name=aegis-elasticsearch" --filter "status=running" -q > "%~dp0.es_stop.tmp" 2>nul
set /p RUNNING_ES_STOP=<"%~dp0.es_stop.tmp" 2>nul
if exist "%~dp0.es_stop.tmp" del "%~dp0.es_stop.tmp" >nul 2>&1

if not defined RUNNING_ES_STOP goto ES_NOT_RUNNING
echo [INFO] Safely stopping container 'aegis-elasticsearch' [preserving volumes and data]...
docker stop aegis-elasticsearch >nul 2>&1
if !ERRORLEVEL! equ 0 (
    echo [OK] Container 'aegis-elasticsearch' stopped safely.
) else (
    echo [WARN] Failed to stop container 'aegis-elasticsearch'.
)
goto CLEANUP_DONE

:ES_NOT_RUNNING
echo [INFO] Container 'aegis-elasticsearch' is not currently running.

:CLEANUP_DONE
echo.
echo ===============================================================================
echo                      AEGIS Services Successfully Stopped
echo ===============================================================================
echo.
