@echo off
setlocal

:: Self-elevate if not running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Directory where the BAT file lives
set SCRIPT_DIR=%~dp0

:: Script name and URL
set PS_SCRIPT=%SCRIPT_DIR%W1X_Debloat_(W10-11).ps1
set PS_URL=https://raw.githubusercontent.com/AdminVin/W1X-Debloat/main/W1X%%20Debloat%%20(W10-11).ps1


:: Download latest version
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Invoke-WebRequest -Uri '%PS_URL%' -OutFile '%PS_SCRIPT%' -UseBasicParsing"

:: Run the script
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%"

endlocal