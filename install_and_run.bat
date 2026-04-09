@echo off
title NetSec Monitor - Setup
echo ================================================
echo   NetSec Monitor - Installing dependencies...
echo ================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.10+ from python.org
    pause
    exit /b 1
)

echo Installing required packages...
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt

echo.
echo ================================================
echo   Starting NetSec Monitor...
echo ================================================
echo.
echo The app will appear in your system tray (next to the clock).
echo A window will open automatically.
echo.

:: Run the app
python main.py

pause
