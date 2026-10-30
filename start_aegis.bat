@echo off
setlocal EnableDelayedExpansion

title AEGIS - Platform Launcher
cd /d "%~dp0"

echo ===============================================================================
echo                AEGIS - Cybersecurity Operations Platform Launcher
echo ===============================================================================
echo.

:: 1. Ensure .env exists (never overwrite existing configuration)
if not exist "%~dp0.env" goto INIT_ENV
echo [INFO] Using existing .env configuration file.
goto ENV_READY

:INIT_ENV
if exist "%~dp0.env.example" (
    echo [INFO] Creating .env from .env.example...
    copy "%~dp0.env.example" "%~dp0.env" >nul
    echo [OK] .env initialized successfully.
) else (
    echo [WARN] Neither .env nor .env.example found. Continuing with defaults.
)

:ENV_READY

:: 2. Training Exclusion and Model Artifact Verification (Mandatory)
echo [INFO] Verifying pre-trained model artifacts (automatic training is disabled)...
set "MISSING_MODELS="
if not exist "%~dp0backend\models\hybrid_detector.joblib" set "MISSING_MODELS=!MISSING_MODELS! hybrid_detector.joblib"
if not exist "%~dp0backend\models\hybrid_detector_xgb.json" set "MISSING_MODELS=!MISSING_MODELS! hybrid_detector_xgb.json"
if not exist "%~dp0backend\models\encrypted_detector.joblib" set "MISSING_MODELS=!MISSING_MODELS! encrypted_detector.joblib"
if not exist "%~dp0backend\models\encrypted_detector_xgb.json" set "MISSING_MODELS=!MISSING_MODELS! encrypted_detector_xgb.json"

if not defined MISSING_MODELS goto MODELS_OK
echo [ERROR] Required pre-trained model artifacts not found:!MISSING_MODELS!
echo [ERROR] Startup policy strictly forbids automatic model training or retraining.
echo [ERROR] Please ensure pre-trained model artifacts are present in backend\models\.
if not defined AEGIS_NO_PAUSE pause
exit /b 1

:MODELS_OK
echo [OK] All required pre-trained model artifacts are present.
echo.

:: 3. Detect and Prioritize Python Environment with Required Dependencies
echo [INFO] Detecting Python environment with required dependencies...
set "PY_FULL_CMD="
set "PY_ENV_LABEL="

:: Check backend\.venv
if not exist "%~dp0backend\.venv\Scripts\python.exe" goto CHECK_BE_VENV
"%~dp0backend\.venv\Scripts\python.exe" -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_FULL_CMD="%~dp0backend\.venv\Scripts\python.exe""
    set "PY_ENV_LABEL=backend\.venv"
    goto PYTHON_DETECTED
) else (
    echo [WARN] Python found at backend\.venv, but required backend packages are missing.
)

:CHECK_BE_VENV
:: Check backend\venv
if not exist "%~dp0backend\venv\Scripts\python.exe" goto CHECK_ROOT_DOTVENV
"%~dp0backend\venv\Scripts\python.exe" -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_FULL_CMD="%~dp0backend\venv\Scripts\python.exe""
    set "PY_ENV_LABEL=backend\venv"
    goto PYTHON_DETECTED
) else (
    echo [WARN] Python found at backend\venv, but required backend packages are missing.
)

:CHECK_ROOT_DOTVENV
:: Check root .venv
if not exist "%~dp0.venv\Scripts\python.exe" goto CHECK_ROOT_VENV
"%~dp0.venv\Scripts\python.exe" -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_FULL_CMD="%~dp0.venv\Scripts\python.exe""
    set "PY_ENV_LABEL=.venv"
    goto PYTHON_DETECTED
) else (
    echo [WARN] Python found at .venv, but required backend packages are missing.
)

:CHECK_ROOT_VENV
:: Check root venv
if not exist "%~dp0venv\Scripts\python.exe" goto CHECK_SYSTEM_PY314
"%~dp0venv\Scripts\python.exe" -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_FULL_CMD="%~dp0venv\Scripts\python.exe""
    set "PY_ENV_LABEL=venv"
    goto PYTHON_DETECTED
) else (
    echo [WARN] Python found at venv, but required backend packages are missing.
)

:CHECK_SYSTEM_PY314
:: Check system py -3.14
py -3.14 -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_FULL_CMD=py -3.14"
    set "PY_ENV_LABEL=System py -3.14"
    goto PYTHON_DETECTED
)

:: Check system python
python -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_FULL_CMD=python"
    set "PY_ENV_LABEL=System python"
    goto PYTHON_DETECTED
)

:: Check generic system py
py -c "import fastapi, uvicorn, pydantic, numpy, pandas, sklearn, xgboost, joblib" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "PY_FULL_CMD=py"
    set "PY_ENV_LABEL=System py"
    goto PYTHON_DETECTED
)

echo [ERROR] No suitable Python interpreter with required dependencies was found.
echo [ERROR] Checked locations: backend\.venv, backend\venv, .venv, venv, and system Python.
echo [ERROR] Required packages: fastapi, uvicorn, pydantic, numpy, pandas, scikit-learn, xgboost, joblib.
echo [ERROR] Automatic dependency installation is disabled by policy.
echo [ERROR] Please install dependencies manually using your virtual environment:
echo        pip install -r backend\requirements.txt
echo.
if not defined AEGIS_NO_PAUSE pause
exit /b 1

:PYTHON_DETECTED
echo [OK] Using Python environment: !PY_ENV_LABEL! [!PY_FULL_CMD!]

:: 4. Detect Node / npm
where npm >nul 2>&1
if !ERRORLEVEL! equ 0 goto NODE_DETECTED
echo [ERROR] npm was not found in PATH.
echo [ERROR] Please install Node.js from https://nodejs.org/ to run the AEGIS frontend.
echo.
if not defined AEGIS_NO_PAUSE pause
exit /b 1

:NODE_DETECTED
echo [OK] Node / npm detected.
echo.

:: 5. Check and Manage Docker Engine and Elasticsearch Container
echo [INFO] Checking Docker engine status...
docker info >nul 2>&1
if !ERRORLEVEL! equ 0 goto DOCKER_RUNNING

echo [WARN] Docker engine is not currently running.
echo [INFO] Searching for Docker Desktop executable...
set "DOCKER_BIN="
if exist "%ProgramFiles%\Docker\Docker\Docker Desktop.exe" set "DOCKER_BIN=%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
if not defined DOCKER_BIN if exist "%LocalAppData%\Programs\DockerDesktop\Docker Desktop.exe" set "DOCKER_BIN=%LocalAppData%\Programs\DockerDesktop\Docker Desktop.exe"
if not defined DOCKER_BIN if exist "%ProgramFiles(x86)%\Docker\Docker\Docker Desktop.exe" set "DOCKER_BIN=%ProgramFiles(x86)%\Docker\Docker\Docker Desktop.exe"
if not defined DOCKER_BIN if exist "%LocalAppData%\Programs\Docker\Docker\Docker Desktop.exe" set "DOCKER_BIN=%LocalAppData%\Programs\Docker\Docker\Docker Desktop.exe"

if not defined DOCKER_BIN (
    echo [WARN] Docker Desktop executable not found in standard paths.
    echo [WARN] Skipping container initialization. Backend will run with demo alerts fallback.
    goto DOCKER_SKIP
)

echo [INFO] Launching Docker Desktop from: "!DOCKER_BIN!"
start "" "!DOCKER_BIN!"
echo [INFO] Waiting up to 30 seconds for Docker daemon to become responsive...
set /a D_RETRIES=0

:WAIT_DOCKER
ping -n 3 127.0.0.1 >nul 2>&1
docker info >nul 2>&1
if !ERRORLEVEL! equ 0 (
    echo [OK] Docker daemon is ready.
    goto DOCKER_RUNNING
)
set /a D_RETRIES+=1
if !D_RETRIES! geq 10 (
    echo [WARN] Docker daemon did not become responsive within timeout.
    echo [WARN] Skipping Elasticsearch startup. Backend will use local demo alerts fallback.
    goto DOCKER_SKIP
)
goto WAIT_DOCKER

:DOCKER_RUNNING
echo [OK] Docker engine is running.
echo [INFO] Verifying Elasticsearch container [aegis-elasticsearch]...

:: Check if aegis-elasticsearch is already running
docker ps --filter "name=aegis-elasticsearch" --filter "status=running" -q > "%~dp0.es_run.tmp" 2>nul
set /p RUNNING_ES=<"%~dp0.es_run.tmp" 2>nul
if exist "%~dp0.es_run.tmp" del "%~dp0.es_run.tmp" >nul 2>&1

if defined RUNNING_ES (
    echo [OK] Container 'aegis-elasticsearch' is already running.
    goto ES_VERIFY
)

:: Check if container exists but is stopped
docker ps -a --filter "name=aegis-elasticsearch" -q > "%~dp0.es_all.tmp" 2>nul
set /p EXISTING_ES=<"%~dp0.es_all.tmp" 2>nul
if exist "%~dp0.es_all.tmp" del "%~dp0.es_all.tmp" >nul 2>&1

if defined EXISTING_ES (
    echo [INFO] Resuming existing container 'aegis-elasticsearch' [preserving all data]...
    docker start aegis-elasticsearch >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] Failed to start existing container 'aegis-elasticsearch'.
        echo [WARN] Backend will operate using local JSON demo fallback.
        goto DOCKER_SKIP
    )
    goto ES_VERIFY
)

:: Container does not exist; create via docker compose (without destroying volumes)
echo [INFO] Deploying Elasticsearch via docker compose [preserving existing volumes]...
docker compose up -d >nul 2>&1
if !ERRORLEVEL! neq 0 (
    docker-compose up -d >nul 2>&1
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] Docker compose deployment command failed.
        echo [WARN] Backend will operate using local JSON demo fallback.
        goto DOCKER_SKIP
    )
)

:ES_VERIFY
:: Verify container is in running state
docker ps --filter "name=aegis-elasticsearch" --filter "status=running" -q > "%~dp0.es_chk.tmp" 2>nul
set /p VERIFIED_ES=<"%~dp0.es_chk.tmp" 2>nul
if exist "%~dp0.es_chk.tmp" del "%~dp0.es_chk.tmp" >nul 2>&1

if defined VERIFIED_ES (
    echo [OK] Container 'aegis-elasticsearch' verified running.
) else (
    echo [WARN] Container 'aegis-elasticsearch' is not running. Operating in fallback mode.
)

:DOCKER_SKIP
echo.

:: 6. Backend Process Management and Health Verification (:8000)
echo [INFO] Checking Backend port 8000 status...
set "BACKEND_STATE=UNKNOWN"
set "PORT8000_PID="
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":8000\>" ^| findstr "LISTENING" 2^>nul') do (
    set "PORT8000_PID=%%a"
)

if not defined PORT8000_PID goto LAUNCH_BACKEND
echo [INFO] Port 8000 is currently occupied by PID: !PORT8000_PID!.
echo [INFO] Verifying if process is the AEGIS Backend service...
curl.exe -s --connect-timeout 2 http://127.0.0.1:8000/api/health > "%~dp0.b_chk.tmp" 2>nul
findstr /i "cyber-threat-prediction" "%~dp0.b_chk.tmp" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    echo [OK] Verified AEGIS Backend is already running on port 8000 [PID: !PORT8000_PID!].
    set "BACKEND_STATE=RUNNING"
    echo !PORT8000_PID!> "%~dp0.aegis_backend.pid"
) else (
    echo [CONFLICT] Port 8000 is in use by an unrelated application [PID: !PORT8000_PID!].
    echo [CONFLICT] AEGIS Backend cannot bind to port 8000.
    echo [INFO] Unrelated process preserved and NOT terminated.
    set "BACKEND_STATE=FAILED"
)
if exist "%~dp0.b_chk.tmp" del "%~dp0.b_chk.tmp" >nul 2>&1
goto BACKEND_DECIDED

:LAUNCH_BACKEND
echo [INFO] Launching AEGIS Backend service on http://127.0.0.1:8000 ...
start "AEGIS Backend" /D "%~dp0backend" cmd /k "!PY_FULL_CMD! -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
echo [INFO] Polling http://127.0.0.1:8000/api/health for backend readiness...
set "BACKEND_STATE=INITIALIZING"
set /a B_RETRIES=0

:POLL_BACKEND
ping -n 2 127.0.0.1 >nul 2>&1
curl.exe -s --connect-timeout 1 http://127.0.0.1:8000/api/health > "%~dp0.b_poll.tmp" 2>nul
findstr /i "cyber-threat-prediction" "%~dp0.b_poll.tmp" >nul 2>&1
if !ERRORLEVEL! equ 0 (
    set "BACKEND_STATE=RUNNING"
    goto BACKEND_POLL_DONE
)
set /a B_RETRIES+=1
if !B_RETRIES! geq 25 (
    set "BACKEND_STATE=FAILED"
    goto BACKEND_POLL_DONE
)
goto POLL_BACKEND

:BACKEND_POLL_DONE
if exist "%~dp0.b_poll.tmp" del "%~dp0.b_poll.tmp" >nul 2>&1

if "!BACKEND_STATE!"=="RUNNING" goto BACKEND_IS_RUNNING
echo [FAILED] AEGIS Backend failed to reach healthy status within 25s.
echo [FAILED] Terminal window remains open. Inspect the AEGIS Backend console for traceback.
goto BACKEND_DECIDED

:BACKEND_IS_RUNNING
for /f "tokens=5" %%p in ('netstat -aon ^| findstr /r ":8000\>" ^| findstr "LISTENING" 2^>nul') do set "NEW_B_PID=%%p"
if defined NEW_B_PID echo !NEW_B_PID!> "%~dp0.aegis_backend.pid"
echo [OK] AEGIS Backend verified RUNNING [HTTP 200 OK, PID: !NEW_B_PID!].

:BACKEND_DECIDED
echo.

:: 7. Frontend Process Management and Health Verification (:5173)
echo [INFO] Checking Frontend port 5173 status...
set "FRONTEND_STATE=UNKNOWN"
set "PORT5173_PID="
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":5173\>" ^| findstr "LISTENING" 2^>nul') do (
    set "PORT5173_PID=%%a"
)

if not defined PORT5173_PID goto LAUNCH_FRONTEND
echo [INFO] Port 5173 is currently occupied by PID: !PORT5173_PID!.
echo [INFO] Verifying if process is the AEGIS Frontend console...
curl.exe -s --connect-timeout 2 http://localhost:5173 > "%~dp0.f_chk.tmp" 2>nul
set "IS_FE="
findstr /i "Cyber Threat Prediction" "%~dp0.f_chk.tmp" >nul 2>&1
if !ERRORLEVEL! equ 0 set "IS_FE=1"
findstr /i "main.tsx" "%~dp0.f_chk.tmp" >nul 2>&1
if !ERRORLEVEL! equ 0 set "IS_FE=1"

if defined IS_FE (
    echo [OK] Verified AEGIS Frontend is already running on port 5173 [PID: !PORT5173_PID!].
    set "FRONTEND_STATE=RUNNING"
    echo !PORT5173_PID!> "%~dp0.aegis_frontend.pid"
) else (
    echo [CONFLICT] Port 5173 is in use by an unrelated application [PID: !PORT5173_PID!].
    echo [CONFLICT] AEGIS Frontend cannot bind to port 5173.
    echo [INFO] Unrelated process preserved and NOT terminated.
    set "FRONTEND_STATE=FAILED"
)
if exist "%~dp0.f_chk.tmp" del "%~dp0.f_chk.tmp" >nul 2>&1
goto FRONTEND_DECIDED

:LAUNCH_FRONTEND
echo [INFO] Launching AEGIS Frontend service on http://localhost:5173 ...
start "AEGIS Frontend" /D "%~dp0frontend" cmd /k "npm run dev"
echo [INFO] Polling http://localhost:5173 for frontend readiness...
set "FRONTEND_STATE=INITIALIZING"
set /a F_RETRIES=0

:POLL_FRONTEND
ping -n 2 127.0.0.1 >nul 2>&1
curl.exe -s --connect-timeout 1 http://localhost:5173 > "%~dp0.f_poll.tmp" 2>nul
set "FE_READY="
findstr /i "Cyber Threat Prediction" "%~dp0.f_poll.tmp" >nul 2>&1
if !ERRORLEVEL! equ 0 set "FE_READY=1"
findstr /i "main.tsx" "%~dp0.f_poll.tmp" >nul 2>&1
if !ERRORLEVEL! equ 0 set "FE_READY=1"

if defined FE_READY (
    set "FRONTEND_STATE=RUNNING"
    goto FRONTEND_POLL_DONE
)
set /a F_RETRIES+=1
if !F_RETRIES! geq 25 (
    set "FRONTEND_STATE=FAILED"
    goto FRONTEND_POLL_DONE
)
goto POLL_FRONTEND

:FRONTEND_POLL_DONE
if exist "%~dp0.f_poll.tmp" del "%~dp0.f_poll.tmp" >nul 2>&1

if "!FRONTEND_STATE!"=="RUNNING" goto FRONTEND_IS_RUNNING
echo [FAILED] AEGIS Frontend failed to reach ready status within 25s.
echo [FAILED] Terminal window remains open. Inspect the AEGIS Frontend console for error logs.
goto FRONTEND_DECIDED

:FRONTEND_IS_RUNNING
for /f "tokens=5" %%p in ('netstat -aon ^| findstr /r ":5173\>" ^| findstr "LISTENING" 2^>nul') do set "NEW_F_PID=%%p"
if defined NEW_F_PID echo !NEW_F_PID!> "%~dp0.aegis_frontend.pid"
echo [OK] AEGIS Frontend verified RUNNING [HTTP 200 OK, PID: !NEW_F_PID!].

:FRONTEND_DECIDED
echo.

:: 8. Final Status Verification
if "!BACKEND_STATE!"=="RUNNING" if "!FRONTEND_STATE!"=="RUNNING" goto STARTUP_SUCCESS

echo ===============================================================================
echo                [WARN] AEGIS Services Failed Health Verification
echo ===============================================================================
echo   Backend State : !BACKEND_STATE!
echo   Frontend State: !FRONTEND_STATE!
echo.
echo   Please inspect the corresponding console windows for error diagnostics.
echo   Run check_aegis.bat to diagnose component status or stop_aegis.bat to clean up.
echo ===============================================================================
echo.
exit /b 1

:STARTUP_SUCCESS
echo ===============================================================================
echo                      AEGIS Services Successfully Initialized!
echo ===============================================================================
echo.
echo   * SOC Operations Console : http://localhost:5173
echo   * FastAPI REST Backend   : http://127.0.0.1:8000
echo   * Interactive API Docs   : http://127.0.0.1:8000/docs
echo   * Elasticsearch Telemetry: http://localhost:9200
echo.
echo   Management Commands:
echo     check_aegis.bat   - View service health and port status
echo     stop_aegis.bat    - Gracefully stop verified AEGIS processes and containers
echo     restart_aegis.bat - Clean restart of all services
echo.
echo   [Tip] Keep the service terminal windows open while operating AEGIS.
echo ===============================================================================
echo.
