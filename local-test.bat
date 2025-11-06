@echo off
REM Local Pre-Commit Testing Script for PANfm (Windows + Docker Desktop)
REM This script helps you test changes locally before committing to GitHub
REM
REM Usage:
REM   1. Make code changes
REM   2. Run this script: local-test.bat
REM   3. Test in browser at http://localhost:3000
REM   4. If all works, commit and push to GitHub
REM
REM What this does:
REM   - Checks Docker Desktop is running
REM   - Stops existing containers
REM   - Rebuilds Docker image with your changes
REM   - Starts fresh container
REM   - Shows logs
REM   - Opens browser automatically

echo ========================================================
echo PANfm Local Testing Workflow (Pre-Commit)
echo ========================================================
echo.
echo This will:
echo   1. Stop existing containers
echo   2. Rebuild with your latest code changes
echo   3. Start fresh container on port 3000
echo   4. Show logs
echo   5. Open browser to http://localhost:3000
echo.
echo Starting in 3 seconds... (Press Ctrl+C to cancel)
timeout /t 3 /nobreak >nul
echo.

REM Check if Docker Desktop is running
echo [1/6] Checking Docker Desktop...
docker version >nul 2>&1
if errorlevel 1 (
    echo    ERROR: Docker Desktop is not running!
    echo.
    echo    Please start Docker Desktop and try again.
    echo    (Look for Docker Desktop icon in system tray)
    echo.
    pause
    exit /b 1
)
echo    Success: Docker Desktop is running
echo.

REM Navigate to script directory
cd /d "%~dp0"

REM Stop and remove existing containers
echo [2/6] Stopping existing containers...
docker compose down >nul 2>&1
echo    Success: Containers stopped
echo.

REM Rebuild Docker image with latest code
echo [3/6] Building Docker image with your changes...
echo    (This may take 1-2 minutes on first run)
echo.
docker compose build --progress=plain
if errorlevel 1 (
    echo.
    echo    ERROR: Docker build failed!
    echo.
    echo    Check the error messages above.
    pause
    exit /b 1
)
echo.
echo    Success: Image built
echo.

REM Start container
echo [4/6] Starting container...
echo.
docker compose up -d
if errorlevel 1 (
    echo.
    echo    ERROR: Container failed to start!
    echo.
    echo    Showing recent logs:
    echo    --------------------------------------------------------
    docker compose logs --tail=30
    echo    --------------------------------------------------------
    echo.
    pause
    exit /b 1
)
echo.
echo    Success: Container started
echo.

REM Wait for application to initialize
echo [5/6] Waiting for application to initialize...
timeout /t 5 /nobreak >nul

REM Check if container is actually running
docker ps | findstr "panfm" >nul
if errorlevel 1 (
    echo    ERROR: Container stopped unexpectedly!
    echo.
    echo    Showing recent logs:
    docker compose logs --tail=30
    pause
    exit /b 1
)
echo    Success: Container is running
echo.

REM Show recent logs
echo [6/6] Recent logs from container:
echo --------------------------------------------------------
docker compose logs --tail=15
echo --------------------------------------------------------
echo.

echo ========================================================
echo SUCCESS: Local testing environment is ready!
echo ========================================================
echo.
echo Your application is running at:
echo   http://localhost:3000
echo.
echo Default credentials:
echo   Username: admin
echo   Password: admin
echo.
echo To view live logs:
echo   docker compose logs -f
echo.
echo To stop the container:
echo   docker compose down
echo.
echo To restart quickly (after code changes):
echo   quick-restart.bat      (keeps data)
echo   restart-docker.bat     (clears data)
echo.

REM Open browser automatically
echo Opening browser in 3 seconds...
timeout /t 3 /nobreak >nul
start http://localhost:3000

echo.
echo =======================================================
echo Testing Checklist:
echo =======================================================
echo.
echo [ ] Login works
echo [ ] Dashboard loads data
echo [ ] Settings page opens
echo [ ] Services tab shows APScheduler/Database status
echo [ ] All features work as expected
echo [ ] No errors in browser console (F12)
echo.
echo If everything works:
echo   1. Stop container: docker compose down
echo   2. Commit your changes: git add . ^&^& git commit -m "..."
echo   3. Push to GitHub: git push origin test
echo.
echo If something is broken:
echo   1. Fix the code
echo   2. Run this script again: local-test.bat
echo   3. Repeat until it works
echo.
pause
