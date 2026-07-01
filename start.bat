@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   Detector - Phishing URL Analyzer
echo ========================================

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

set "VENV_DIR=%PROJECT_DIR%venv"

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [*] Creating Python virtual environment...
    python -m venv "%VENV_DIR%"
)

echo [*] Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"

echo [*] Installing dependencies...
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo [*] Ensuring results directory exists...
if not exist results mkdir results
if not exist instance mkdir instance

echo [*] Starting Flask application...
echo     Open http://127.0.0.1:5000 in your browser
echo ========================================
echo.

set FLASK_ENV=development
set FLASK_APP=run.py

python run.py
pause
