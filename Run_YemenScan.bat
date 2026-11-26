@echo off
title YemenScan Platform Launcher
chcp 65001 >nul
echo ========================================================
echo          YemenScan Security Platform - Start
echo ========================================================
echo.

:: Change directory to script location
cd /d "%~dp0"

:: 1. Detect Python executable
set "PYTHON_CMD=python"
if exist "%~dp0venv\Scripts\python.exe" set "PYTHON_CMD=%~dp0venv\Scripts\python.exe"
if exist "%~dp0.venv\Scripts\python.exe" set "PYTHON_CMD=%~dp0.venv\Scripts\python.exe"
if "%PYTHON_CMD%"=="python" (
    where python >nul 2>&1
    if errorlevel 1 (
        if exist "C:\Python314\python.exe" set "PYTHON_CMD=C:\Python314\python.exe"
    )
)

:: 2. Terminate any previous instance on Port 8000 (closes previous server window)
echo [*] [1/4] Checking and closing any previous YemenScan instances...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000 ^| findstr LISTENING') do (
    taskkill /F /T /PID %%a >nul 2>&1
)

:: 3. Start PostgreSQL, Redis, and Celery Worker containers in Docker
echo [*] [2/4] Starting PostgreSQL, Redis, and Celery Worker containers in Docker...
docker compose up -d db redis worker >nul 2>&1
if errorlevel 1 (
    echo [!] Note: Docker is not available. Using local SQLite database yemenscan.db
) else (
    echo [+] Docker services db, redis, worker started cleanly.
    ping 127.0.0.1 -n 3 >nul
)

:: 4. Initialize Database
echo [*] [3/4] Initializing database schema...
call "%PYTHON_CMD%" init_db.py

:: 5. Launch FastAPI Backend in a Dedicated Window
echo [*] [4/4] Starting FastAPI backend on http://127.0.0.1:8000 ...
start "YemenScan Server - FastAPI" /d "%~dp0" cmd /k %PYTHON_CMD% -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload

:: Wait for server to bind to port 8000
echo [*] Waiting for server to initialize on http://127.0.0.1:8000 ...
set "WAIT_ATTEMPTS=0"
:wait_for_server
set /a WAIT_ATTEMPTS+=1
ping 127.0.0.1 -n 2 >nul
netstat -aon | findstr :8000 | findstr LISTENING >nul 2>&1
if not errorlevel 1 goto server_ready
if %WAIT_ATTEMPTS% lss 15 goto wait_for_server

:server_ready

:: 6. Launch Web Dashboard in Browser
echo [*] Launching YemenScan Dashboard in browser...
start http://127.0.0.1:8000

echo.
echo ========================================================
echo  [+] YemenScan Platform is LIVE!
echo  - Server Logs: Running in the server console window.
echo  - Web Dashboard: http://127.0.0.1:8000
echo  - To stop the platform: Run Stop_YemenScan.bat
echo ========================================================
echo.
ping 127.0.0.1 -n 3 >nul
exit
