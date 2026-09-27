@echo off
setlocal
 title Gavin Network Monitor Downloader

REM Set this to your GitHub username after creating the repository.
set "REPO_OWNER=YOUR_GITHUB_USERNAME"
set "REPO_NAME=GavinNetworkMonitor"
set "API_URL=https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/releases/latest"
set "DEST=%USERPROFILE%\Downloads\GavinNetworkMonitor"

if "%REPO_OWNER%"=="YOUR_GITHUB_USERNAME" (
  echo Please edit this file and replace YOUR_GITHUB_USERNAME with your GitHub username.
  echo Then save it and run it again.
  pause
  exit /b 1
)

where powershell.exe >nul 2>&1 || (
  echo Windows PowerShell was not found.
  pause
  exit /b 1
)

if not exist "%DEST%" mkdir "%DEST%"
echo Checking the latest GitHub release...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop'; $release=Invoke-RestMethod -Headers @{'User-Agent'='GavinNetworkMonitor-Downloader'} -Uri '%API_URL%'; $asset=$release.assets | Where-Object { $_.name -like '*.zip' } | Select-Object -First 1; if (-not $asset) { throw 'No ZIP asset was found. Publish a ZIP file in the GitHub release first.' }; $zip=Join-Path '%DEST%' $asset.name; Invoke-WebRequest -Headers @{'User-Agent'='GavinNetworkMonitor-Downloader'} -Uri $asset.browser_download_url -OutFile $zip; Expand-Archive -LiteralPath $zip -DestinationPath '%DEST%' -Force; Write-Host ('Downloaded release ' + $release.tag_name + ' to ' + '%DEST%')"
if errorlevel 1 (
  echo Download failed. Check the repository name, username, internet connection, and published GitHub release.
  pause
  exit /b 1
)
echo.
echo Done! Files are in: %DEST%
echo Open the extracted folder and run Run_GavinNetworkMonitor.bat
pause
