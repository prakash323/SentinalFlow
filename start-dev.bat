@echo off
rem Starts the full SentinelFlow dev stack. Each service gets its own window.
rem Prerequisites: Docker Desktop, JDK 21, Maven on PATH, Node 20+, Python 3.11+.
setlocal
cd /d "%~dp0"

echo [1/4] Starting PostgreSQL + Kafka...
docker compose up -d
if errorlevel 1 (
    echo Docker failed to start the infrastructure. Is Docker Desktop running?
    exit /b 1
)

echo [2/4] Starting the ML service (warm-up takes ~2 minutes)...
start "SentinelFlow ML service" cmd /k "cd /d %~dp0ml-service\anomaly-detection && start_ml_windows.bat"

echo [3/4] Starting the Spring Boot backend...
start "SentinelFlow backend" cmd /k "cd /d %~dp0backend\backend && mvn spring-boot:run"

echo [4/4] Starting the console...
start "SentinelFlow console" cmd /k "cd /d %~dp0frontend && (if not exist node_modules npm install) && npm run dev"

echo.
echo Console:  http://localhost:5173
echo API docs: http://localhost:8080/swagger-ui.html  (admin login)
endlocal
