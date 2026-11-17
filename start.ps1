# Guardrailed AI Action Gateway - PowerShell Launcher
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting Guardrailed AI Action & API Orchestration Gateway" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "frontend"
$VenvPython = Join-Path $RootDir "venv\Scripts\python.exe"
$VenvUvicorn = Join-Path $RootDir "venv\Scripts\uvicorn.exe"

if (-not (Test-Path $VenvUvicorn)) {
    Write-Host "[!] Virtual environment not found at $RootDir\venv." -ForegroundColor Red
    Write-Host "    Please run: python -m venv venv; .\venv\Scripts\pip install -r backend\requirements.txt" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n[1/2] Launching FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$BackendDir'; & '$VenvUvicorn' app.main:app --reload --host 127.0.0.1 --port 8000"

Write-Host "[2/2] Launching React Enterprise Frontend on http://localhost:5173..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$FrontendDir'; npm run dev"

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Both servers are starting in separate windows!" -ForegroundColor Green
Write-Host "  -> Backend Swagger API Docs: http://127.0.0.1:8000/docs" -ForegroundColor Yellow
Write-Host "  -> Enterprise Dashboard UI:  http://localhost:5173" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
