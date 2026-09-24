@echo off
setlocal enabledelayedexpansion
title CipherGuard - Dual-Layer Wireless and VPN Security Platform
cls

REM Ensure we are running from the project directory containing cipherguard
if exist "%~dp0cipherguard\cli.py" (
    cd /d "%~dp0"
) else if exist "%~dp0cipherguard\cipherguard\cli.py" (
    cd /d "%~dp0cipherguard"
) else if exist "%~dp0final\cipherguard\cipherguard\cli.py" (
    cd /d "%~dp0final\cipherguard"
) else if exist "%~dp0..\cipherguard\cli.py" (
    cd /d "%~dp0.."
) else (
    cd /d "%~dp0"
)

echo ======================================================================
echo   CIPHERGUARD - DUAL-LAYER SECURITY PLATFORM (Wi-Fi + IPsec/VPN)
echo   SIH26160 / NTRO Compliance - NIST SP 800-77 and RFC 8247 Hardening
echo ======================================================================
echo.

set "PY_EXE="

REM -------------------------------------------------------------------------
REM Step 1: Detect a Python interpreter that has dependencies installed
REM -------------------------------------------------------------------------

REM 1. Active virtual environment in shell
if defined VIRTUAL_ENV if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
    "%VIRTUAL_ENV%\Scripts\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%VIRTUAL_ENV%\Scripts\python.exe"
)
if defined PY_EXE goto :python_ready

REM 2. Project-local virtual environments (.venv or venv)
if exist "%CD%\.venv\Scripts\python.exe" (
    "%CD%\.venv\Scripts\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%CD%\.venv\Scripts\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "%CD%\venv\Scripts\python.exe" (
    "%CD%\venv\Scripts\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%CD%\venv\Scripts\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%~dp0.venv\Scripts\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "%~dp0venv\Scripts\python.exe" (
    "%~dp0venv\Scripts\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%~dp0venv\Scripts\python.exe"
)
if defined PY_EXE goto :python_ready

REM 3. Python on system PATH
python -c "import numpy" >nul 2>nul && set "PY_EXE=python"
if defined PY_EXE goto :python_ready

REM 4. Windows py launcher
py -3 -c "import numpy" >nul 2>nul && set "PY_EXE=py -3"
if defined PY_EXE goto :python_ready

REM 5. WindowsApps / Microsoft Store Python
if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" (
    "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe"
)
if defined PY_EXE goto :python_ready

REM 6. Standard installed Python distributions in LocalAppData
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
)
if defined PY_EXE goto :python_ready

REM 7. Program Files / System-wide Python distributions
if exist "%ProgramFiles%\Python312\python.exe" (
    "%ProgramFiles%\Python312\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%ProgramFiles%\Python312\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "%ProgramFiles%\Python311\python.exe" (
    "%ProgramFiles%\Python311\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%ProgramFiles%\Python311\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "%ProgramFiles%\Python310\python.exe" (
    "%ProgramFiles%\Python310\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%ProgramFiles%\Python310\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "C:\Python312\python.exe" (
    "C:\Python312\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=C:\Python312\python.exe"
)
if defined PY_EXE goto :python_ready

if exist "C:\Python311\python.exe" (
    "C:\Python311\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=C:\Python311\python.exe"
)
if defined PY_EXE goto :python_ready

REM 8. User profile venv (only if numpy is verified installed)
if exist "%USERPROFILE%\venv\Scripts\python.exe" (
    "%USERPROFILE%\venv\Scripts\python.exe" -c "import numpy" >nul 2>nul && set "PY_EXE=%USERPROFILE%\venv\Scripts\python.exe"
)
if defined PY_EXE goto :python_ready

REM -------------------------------------------------------------------------
REM Step 2: Fallback - locate any Python and install missing dependencies
REM -------------------------------------------------------------------------
if defined VIRTUAL_ENV if exist "%VIRTUAL_ENV%\Scripts\python.exe" set "PY_EXE=%VIRTUAL_ENV%\Scripts\python.exe"
if not defined PY_EXE if exist "%CD%\.venv\Scripts\python.exe" set "PY_EXE=%CD%\.venv\Scripts\python.exe"
if not defined PY_EXE if exist "%CD%\venv\Scripts\python.exe" set "PY_EXE=%CD%\venv\Scripts\python.exe"
if not defined PY_EXE if exist "%~dp0.venv\Scripts\python.exe" set "PY_EXE=%~dp0.venv\Scripts\python.exe"
if not defined PY_EXE if exist "%~dp0venv\Scripts\python.exe" set "PY_EXE=%~dp0venv\Scripts\python.exe"
if not defined PY_EXE where python >nul 2>nul && set "PY_EXE=python"
if not defined PY_EXE where py >nul 2>nul && set "PY_EXE=py -3"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" set "PY_EXE=%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
if not defined PY_EXE if exist "%ProgramFiles%\Python312\python.exe" set "PY_EXE=%ProgramFiles%\Python312\python.exe"
if not defined PY_EXE if exist "%ProgramFiles%\Python311\python.exe" set "PY_EXE=%ProgramFiles%\Python311\python.exe"
if not defined PY_EXE if exist "C:\Python312\python.exe" set "PY_EXE=C:\Python312\python.exe"
if not defined PY_EXE if exist "C:\Python311\python.exe" set "PY_EXE=C:\Python311\python.exe"

if not defined PY_EXE (
    echo [ERROR] Python 3.10+ was not found on your system.
    echo Please install Python from https://www.python.org/downloads/
    echo and ensure "Add Python to PATH" is checked during installation.
    echo.
    pause
    exit /b 1
)

echo [*] Python interpreter found: !PY_EXE!
echo [*] Installing required dependencies from requirements.txt...
echo.
!PY_EXE! -m pip install -r requirements.txt
if !errorlevel! neq 0 (
    echo.
    echo [ERROR] Failed to install dependencies automatically.
    echo Please run: !PY_EXE! -m pip install -r requirements.txt
    pause
    exit /b 1
)

:python_ready

echo [*] Project Directory: %CD%
echo [*] Python Interpreter: !PY_EXE!

REM Ensure PYTHONPATH includes current project directory for seamless module resolution
set "PYTHONPATH=%CD%;!PYTHONPATH!"

REM -------------------------------------------------------------------------
REM Step 3: Verify trained ML models and synchronize live telemetry
REM -------------------------------------------------------------------------
if not exist "models\cnn.npz" (
    echo [*] Pre-trained models not found in models/. Generating baseline model...
    !PY_EXE! -m cipherguard.cli train --samples 30 --epochs 20
    echo.
)

if exist "scripts\sync_live_wifi.py" (
    echo [*] Auditing local wireless RF spectrum and hardware telemetry...
    !PY_EXE! scripts\sync_live_wifi.py
    echo.
)

REM -------------------------------------------------------------------------
REM Step 4: Detect dynamic LAN IP for multi-device access
REM -------------------------------------------------------------------------
set "LAN_IP="
for /f "tokens=4" %%a in ('route print 0.0.0.0 2^>nul ^| findstr "\<0.0.0.0\>"') do (
    if not defined LAN_IP if not "%%a"=="0.0.0.0" set "LAN_IP=%%a"
)

echo [*] Launching CipherGuard Multi-Device Security Dashboard...
echo [*] Local Workstation URL: http://127.0.0.1:8000/
if defined LAN_IP (
    echo [*] Multi-Device LAN URL:   http://!LAN_IP!:8000/  [Open on phones / tablets / other PCs]
) else (
    echo [*] Multi-Device LAN URL:   http://0.0.0.0:8000/  [Check local IP for LAN access]
)
echo [*] Opening your default web browser...
echo [*] (Keep this window open. Press Ctrl+C anytime to stop the server.)
echo ======================================================================
echo.

REM Open browser in background
start "" "http://127.0.0.1:8000/"

REM Start dashboard server bound to 0.0.0.0 with insecure-bind for multi-device LAN access
!PY_EXE! -m cipherguard.cli serve --host 0.0.0.0 --port 8000 --insecure-bind %*

REM If server exited abnormally (not from Ctrl+C / SIGINT 130 or STATUS_CONTROL_C_EXIT)
if !errorlevel! neq 0 if !errorlevel! neq 130 if !errorlevel! neq -1073741510 (
    echo.
    echo [ERROR] Server exited with error code: !errorlevel!
    pause
)
