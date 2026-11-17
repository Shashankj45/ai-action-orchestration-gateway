@echo off
title Guardrailed AI Action Gateway Launcher
echo ==========================================================
echo  Starting Guardrailed AI Action ^& API Orchestration Gateway
echo ==========================================================

set "ROOT_DIR=%~dp0"
set "BACKEND_DIR=%ROOT_DIR%backend"
set "FRONTEND_DIR=%ROOT_DIR%frontend"
set "UVICORN=%ROOT_DIR%venv\Scripts\uvicorn.exe"

if not exist "%UVICORN%" (
    echo [!] Virtual environment not found at %ROOT_DIR%venv.
    echo     Please create venv and install dependencies first.
    pause
    exit /b 1
)

echo [1/2] Launching FastAPI Backend on http://127.0.0.1:8000...
start "FastAPI Gateway Backend" cmd /k "cd /d %BACKEND_DIR% && ..\venv\Scripts\uvicorn.exe app.main:app --reload --host 127.0.0.1 --port 8000"

echo [2/2] Launching React Enterprise Frontend on http://localhost:5173...
start "React Gateway Frontend" cmd /k "cd /d %FRONTEND_DIR% && npm run dev"

echo ==========================================================
echo  Both servers have been launched in separate windows!
echo   - Backend Swagger API: http://127.0.0.1:8000/docs
echo   - Enterprise UI Dashboard: http://localhost:5173
echo ==========================================================
