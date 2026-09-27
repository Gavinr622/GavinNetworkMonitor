@echo off
title Gavin Network Monitor - Dependency Setup
cd /d "%~dp0"
echo ==========================================
echo Gavin Network Monitor - Dependency Setup
echo ==========================================
echo.
where py >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.10+ from https://www.python.org/downloads/
  echo Enable the Python launcher during installation.
  pause
  exit /b 1
)
py --version
echo.
echo Installing Python packages from requirements.txt...
py -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo Dependency installation failed. Check your internet connection and Python installation.
  pause
  exit /b 1
)
echo.
echo Dependencies installed successfully.
echo Npcap is a separate Windows install required for packet capture: https://npcap.com/
echo Run Run_GavinNetworkMonitor.bat to start the app.
pause
