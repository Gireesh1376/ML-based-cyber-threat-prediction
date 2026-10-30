@echo off
setlocal EnableDelayedExpansion

title AEGIS - System Health Check
cd /d "%~dp0"

echo ===============================================================================
echo                    AEGIS - Platform Health and Availability Check
echo ===============================================================================
echo.

:: 1. Python Environment and Pre-trained Model Check
echo [1/5] Checking Python Environment and Pre-trained Model Artifacts...
set "DETECTED_PY="
set "PY_STATUS=MISSING_DEPS"

:: Check virtual environments first
if exist "%~dp0backend\.venv\Scripts\python.exe" (
    "%~dp0backend\.venv\Scripts\python.exe" -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set "DETECTED_PY=backend\.venv"
        set "PY_STATUS=READY"
        goto PY_CHECKED
    )
)
if exist "%~dp0backend\venv\Scripts\python.exe" (
    "%~dp0backend\venv\Scripts\python.exe" -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set "DETECTED_PY=backend\venv"
        set "PY_STATUS=READY"
        goto PY_CHECKED
    )
)
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        set "DETECTED_PY=.venv"
        set "PY_STATUS=READY"
        goto PY_CHECKED
    )
)

:: Check system python interpreters
py -3.14 -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "DETECTED_PY=System py -3.14"
    set "PY_STATUS=READY"
    goto PY_CHECKED
)
python -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "DETECTED_PY=System python"
    set "PY_STATUS=READY"
    goto PY_CHECKED
)

:PY_CHECKED
if "!PY_STATUS!"=="READY" (
    echo   - Python Environment : READY [!DETECTED_PY!]
) else (
    echo   - Python Environment : MISSING DEPENDENCIES or NOT FOUND
)

:: Check pre-trained model artifacts
set "MISSING_MODELS_CHK="
if not exist "%~dp0backend\models\hybrid_detector.joblib" set "MISSING_MODELS_CHK=!MISSING_MODELS_CHK! hybrid_detector.joblib"
if not exist "%~dp0backend\models\hybrid_detector_xgb.json" set "MISSING_MODELS_CHK=!MISSING_MODELS_CHK! hybrid_detector_xgb.json"
if not exist "%~dp0backend\models\encrypted_detector.joblib" set "MISSING_MODELS_CHK=!MISSING_MODELS_CHK! encrypted_detector.joblib"
if not exist "%~dp0backend\models\encrypted_detector_xgb.json" set "MISSING_MODELS_CHK=!MISSING_MODELS_CHK! encrypted_detector_xgb.json"

if defined MISSING_MODELS_CHK (
    echo   - Trained Model Files: MISSING [!MISSING_MODELS_CHK!]
) else (
    echo   - Trained Model Files: VERIFIED [All 4 foundational model artifacts present]
)
echo.

:: 2. Check Docker and Container Status
echo [2/5] Checking Docker Engine and Container Health...
docker info >nul 2>&1
if !ERRORLEVEL! neq 0 goto DOCKER_OFFLINE

echo   - Docker Engine      : ONLINE
docker ps --filter "name=aegis-elasticsearch" --format "{{.Status}}" > "%~dp0.es_status.tmp" 2>nul
set /p ES_STATUS=<"%~dp0.es_status.tmp" 2>nul
if exist "%~dp0.es_status.tmp" del "%~dp0.es_status.tmp" >nul 2>&1

if defined ES_STATUS (
    echo   - aegis-elasticsearch: RUNNING [!ES_STATUS!]
) else (
    docker ps -a --filter "name=aegis-elasticsearch" -q > "%~dp0.es_all_chk.tmp" 2>nul
    set /p ES_EXISTS=<"%~dp0.es_all_chk.tmp" 2>nul
    if exist "%~dp0.es_all_chk.tmp" del "%~dp0.es_all_chk.tmp" >nul 2>&1
    if defined ES_EXISTS (
        echo   - aegis-elasticsearch: STOPPED [Container exists, not running]
    ) else (
        echo   - aegis-elasticsearch: NOT CREATED
    )
)
goto DOCKER_DONE

:DOCKER_OFFLINE
echo   - Docker Engine      : OFFLINE [Docker Desktop is not running]
echo   - aegis-elasticsearch: UNKNOWN [Docker unavailable]

:DOCKER_DONE
echo.

:: 3. Check Elasticsearch HTTP Service (:9200)
echo [3/5] Checking Elasticsearch Endpoint (http://localhost:9200)...
set "ES_HTTP=OFFLINE"
curl.exe -s --connect-timeout 2 http://localhost:9200 > "%~dp0.es_http.tmp" 2>nul
findstr /i "tagline" "%~dp0.es_http.tmp" >nul 2>&1
if !ERRORLEVEL! equ 0 set "ES_HTTP=ONLINE"
if exist "%~dp0.es_http.tmp" del "%~dp0.es_http.tmp" >nul 2>&1

if "!ES_HTTP!"=="ONLINE" (
    echo   - Elasticsearch HTTP : HEALTHY [HTTP 200 OK]
) else (
    echo   - Elasticsearch HTTP : OFFLINE / UNREACHABLE [Operating in fallback mode]
)
echo.

:: 4. Check Backend API (:8000)
echo [4/5] Checking Backend API (http://127.0.0.1:8000/api/health)...
set "BACKEND_PID="
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":8000\>" ^| findstr "LISTENING" 2^>nul') do set "BACKEND_PID=%%a"

if defined BACKEND_PID (
    echo   - Port 8000 Status   : LISTENING [PID: !BACKEND_PID!]
    curl.exe -s --connect-timeout 2 http://127.0.0.1:8000/api/health > "%~dp0.b_health.tmp" 2>nul
    findstr /i "cyber-threat-prediction" "%~dp0.b_health.tmp" >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        echo   - Backend API Health : HEALTHY [HTTP 200 OK - RUNNING]
    ) else (
        echo   - Backend API Health : CONFLICT / UNRESPONSIVE [Not verified as AEGIS]
    )
    if exist "%~dp0.b_health.tmp" del "%~dp0.b_health.tmp" >nul 2>&1
) else (
    echo   - Port 8000 Status   : NOT LISTENING [Backend is OFFLINE]
    echo   - Backend API Health : OFFLINE
)
echo.

:: 5. Check Frontend (:5173)
echo [5/5] Checking Frontend Console (http://localhost:5173)...
set "FRONTEND_PID="
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":5173\>" ^| findstr "LISTENING" 2^>nul') do set "FRONTEND_PID=%%a"

if defined FRONTEND_PID (
    echo   - Port 5173 Status   : LISTENING [PID: !FRONTEND_PID!]
    curl.exe -s --connect-timeout 2 http://localhost:5173 > "%~dp0.f_health.tmp" 2>nul
    set "IS_FE_RUNNING="
    findstr /i "Cyber Threat Prediction" "%~dp0.f_health.tmp" >nul 2>&1
    if !ERRORLEVEL! equ 0 set "IS_FE_RUNNING=1"
    findstr /i "main.tsx" "%~dp0.f_health.tmp" >nul 2>&1
    if !ERRORLEVEL! equ 0 set "IS_FE_RUNNING=1"
    
    if defined IS_FE_RUNNING (
        echo   - Frontend Status    : HEALTHY [HTTP 200 OK - RUNNING]
    ) else (
        echo   - Frontend Status    : CONFLICT / UNRESPONSIVE [Not verified as AEGIS]
    )
    if exist "%~dp0.f_health.tmp" del "%~dp0.f_health.tmp" >nul 2>&1
) else (
    echo   - Port 5173 Status   : NOT LISTENING [Frontend is OFFLINE]
    echo   - Frontend Status    : OFFLINE
)
echo.

echo ===============================================================================
echo Status Check Complete.
echo ===============================================================================
echo.
