@echo off
setlocal enabledelayedexpansion
title CipherGuard - Dual-Layer Wireless and VPN Security Platform
cls

:: Ensure we are running from the directory where this script is located
cd /d "%~dp0"

echo ======================================================================
echo   CIPHERGUARD - DUAL-LAYER SECURITY PLATFORM (Wi-Fi + IPsec/VPN)
echo   SIH26160 / NTRO Compliance - NIST SP 800-77 and RFC 8247 Hardening
echo ======================================================================
echo.

set "PY_EXE="

:: 1. Check virtual environments (user profile venv and local project venv)
if exist "%USERPROFILE%\venv\Scripts\python.exe" (
    set "PY_EXE=%USERPROFILE%\venv\Scripts\python.exe"
)
if not defined PY_EXE if exist "%~dp0venv\Scripts\python.exe" (
    set "PY_EXE=%~dp0venv\Scripts\python.exe"
)
if not defined PY_EXE if exist "%~dp0..\venv\Scripts\python.exe" (
    set "PY_EXE=%~dp0..\venv\Scripts\python.exe"
)

:: 2. Check installed Python distributions (3.12, 3.11, 3.10)
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
)
if not defined PY_EXE if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
)

:: 3. Check py launcher
if not defined PY_EXE (
    where py >nul 2>nul
    if !errorlevel! equ 0 (
        set "PY_EXE=py -3"
    )
)

:: 4. Check python on PATH
if not defined PY_EXE (
    where python >nul 2>nul
    if !errorlevel! equ 0 (
        set "PY_EXE=python"
    )
)

:: 5. Verify python is available
if not defined PY_EXE (
    echo [ERROR] Python 3.10+ was not found on your system.
    echo Please install Python from https://www.python.org/downloads/
    echo and ensure "Add Python to PATH" is checked during installation.
    echo.
    pause
    exit /b 1
)

echo [*] Project Directory: %CD%
echo [*] Python Interpreter: !PY_EXE!

:: Ensure PYTHONPATH includes current project directory for seamless module resolution
set "PYTHONPATH=%CD%;!PYTHONPATH!"

:: 6. Pre-scan and synchronize live physical Wi-Fi & VPN telemetry
if exist "scripts\sync_live_wifi.py" (
    echo [*] Auditing local wireless RF spectrum & hardware telemetry...
    !PY_EXE! scripts\sync_live_wifi.py
    echo.
)

echo [*] Launching CipherGuard Multi-Device Security Dashboard...
echo [*] Local Workstation URL: http://127.0.0.1:8000/
echo [*] Multi-Device LAN URL:   http://192.168.1.35:8000/  (Open on phones / tablets / other PCs)
echo [*] Opening your default web browser...
echo [*] (Keep this window open. Press Ctrl+C anytime to stop the server.)
echo ======================================================================
echo.

:: Open browser in background
start "" "http://127.0.0.1:8000/"

:: Start dashboard server bound to 0.0.0.0 with insecure-bind for multi-device LAN access
!PY_EXE! -m cipherguard.cli serve --host 0.0.0.0 --port 8000 --insecure-bind

if !errorlevel! neq 0 (
    echo.
    echo [!] Server exited with an error code.
    pause
)
