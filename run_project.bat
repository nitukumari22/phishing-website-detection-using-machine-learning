@echo off
echo ===================================================
echo   PHISHING WEBSITE DETECTION PORTAL - LAUNCHER
echo ===================================================
echo.
echo [1/3] Starting backend FastAPI server on http://127.0.0.1:8000 ...
start "PhishShield Backend API" cmd /k "python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload"

echo.
echo [2/3] Starting frontend HTTP server on http://127.0.0.1:8080 ...
start "PhishShield Frontend UI" cmd /k "python -m http.server 8080 --directory frontend"

echo.
echo [3/3] Opening your browser...
timeout /t 3 >nul
start http://127.0.0.1:8080

echo.
echo Portal successfully launched!
echo Keep the command prompt windows running to maintain the servers.
echo Backend API docs: http://127.0.0.1:8000/docs
echo Frontend website: http://127.0.0.1:8080
echo ===================================================
pause
