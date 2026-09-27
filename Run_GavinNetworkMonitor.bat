@echo off
title Gavin Network Monitor
cd /d "%~dp0"
echo Starting Gavin Network Monitor...
echo.
py app.py
if errorlevel 1 (
    echo.
    echo Gavin Network Monitor exited with an error.
    pause
)
