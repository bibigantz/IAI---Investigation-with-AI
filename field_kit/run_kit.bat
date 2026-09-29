@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Not running as Administrator -- some artifacts ($MFT, SAM/SECURITY
    echo     hives, Autoruns^) will be skipped. Recommended: right-click this
    echo     file and choose "Run as administrator" instead.
    echo.
    timeout /t 4 >nul
)

run_kit.exe %*
