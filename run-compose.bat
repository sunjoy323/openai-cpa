@echo off
setlocal

set "MODE=%~1"

if "%MODE%"=="" goto :usage

where docker >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Docker command not found. Make sure Docker is installed and available in PATH.
    exit /b 1
)

if /I "%MODE%"=="local" goto :local
if /I "%MODE%"=="remote" goto :remote
if /I "%MODE%"=="pull" goto :pull
if /I "%MODE%"=="down" goto :down
if /I "%MODE%"=="logs" goto :logs

echo [ERROR] Unsupported mode: %MODE%
goto :usage

:local
echo [INFO] Build from local source and start containers...
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build --force-recreate
exit /b %errorlevel%

:remote
echo [INFO] Start containers with the current remote image...
docker compose up -d
exit /b %errorlevel%

:pull
echo [INFO] Pull the latest remote image and recreate containers...
docker compose pull
if errorlevel 1 exit /b %errorlevel%
docker compose up -d --force-recreate
exit /b %errorlevel%

:down
echo [INFO] Stop and remove containers...
docker compose down
exit /b %errorlevel%

:logs
echo [INFO] Follow container logs...
docker compose logs -f
exit /b %errorlevel%

:usage
echo.
echo Usage:
echo   run-compose.bat local   ^<-- Build from local source and start
echo   run-compose.bat remote  ^<-- Start with the current remote image
echo   run-compose.bat pull    ^<-- Pull the latest remote image and start
echo   run-compose.bat down    ^<-- Stop and remove containers
echo   run-compose.bat logs    ^<-- Show live logs
echo.
exit /b 1
