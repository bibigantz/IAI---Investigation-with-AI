@echo off
setlocal
rem Dev-only convenience script -- rebuilds dist\IAI_Collection_Kit from the
rem current collectors\collector.py, tools\, and collector_paths.json.
rem Run this on the DEVELOPMENT machine, not the field kit itself.
cd /d "%~dp0.."

where python >nul 2>nul
if %errorlevel% neq 0 (
    where py >nul 2>nul
    if %errorlevel% neq 0 (
        echo [-] Python was not found on this machine. Install Python 3.8+ and try again.
        pause
        exit /b 1
    )
    set PYCMD=py
) else (
    set PYCMD=python
)

%PYCMD% -c "import PyInstaller" >nul 2>nul
if %errorlevel% neq 0 (
    echo [*] PyInstaller not found -- installing it now...
    %PYCMD% -m pip install pyinstaller
    if %errorlevel% neq 0 (
        echo [-] Failed to install PyInstaller. Aborting.
        pause
        exit /b 1
    )
)

echo [*] Rebuilding IAI Field Collection Kit...
%PYCMD% build_field_kit.py
if %errorlevel% neq 0 (
    echo [-] Build failed -- see errors above.
    pause
    exit /b 1
)

echo.
echo [+] Rebuild complete. See dist\IAI_Collection_Kit\
pause
