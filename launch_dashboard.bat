@echo off
setlocal enabledelayedexpansion
title CipherGuard
cls

REM UTF-8 console output, for network names and symbols in the server's log
chcp 65001 >nul 2>nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

REM -------------------------------------------------------------------------
REM Arguments: --lan serves other devices on the network, behind a token.
REM --port N changes the port. Without --lan the dashboard listens on this
REM machine only. Everything else is passed through to "cipherguard serve".
REM -------------------------------------------------------------------------
set "LAN_MODE="
set "PORT=8000"
set "SERVE_ARGS="
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--lan" (
    set "LAN_MODE=1"
) else if /i "%~1"=="--port" (
    set "PORT=%~2"
    shift
) else (
    set "SERVE_ARGS=!SERVE_ARGS! %1"
)
shift
goto :parse_args
:args_done

REM Run from the directory this script is in: the project root.
cd /d "%~dp0"
if not exist "cipherguard\cli.py" (
    echo [ERROR] launch_dashboard.bat must stay in the CipherGuard project folder.
    pause
    exit /b 1
)

echo ======================================================================
echo   CipherGuard - IPsec and Wi-Fi cryptographic assessment
echo ======================================================================
echo.

REM -------------------------------------------------------------------------
REM Step 1: Find a Python that already has the dependencies.
REM PY_EXE holds the whole command, quoted where it is a path, so it is
REM always used as  !PY_EXE! -m ...
REM -------------------------------------------------------------------------
set "PY_EXE="

if defined VIRTUAL_ENV if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
    "%VIRTUAL_ENV%\Scripts\python.exe" -c "import numpy, fastapi" >nul 2>nul && set PY_EXE="%VIRTUAL_ENV%\Scripts\python.exe"
)
if defined PY_EXE goto :python_ready

for %%d in (.venv venv) do (
    if not defined PY_EXE if exist "%CD%\%%d\Scripts\python.exe" (
        "%CD%\%%d\Scripts\python.exe" -c "import numpy, fastapi" >nul 2>nul && set PY_EXE="%CD%\%%d\Scripts\python.exe"
    )
)
if defined PY_EXE goto :python_ready

python -c "import numpy, fastapi" >nul 2>nul && set "PY_EXE=python"
if defined PY_EXE goto :python_ready

py -3 -c "import numpy, fastapi" >nul 2>nul && set "PY_EXE=py -3"
if defined PY_EXE goto :python_ready

REM -------------------------------------------------------------------------
REM Step 2: None has them. Create a virtual environment in this folder and
REM install there. Nothing is installed into a system-wide Python.
REM -------------------------------------------------------------------------
set "BASE_PY="
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "BASE_PY=python"
if not defined BASE_PY py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul && set "BASE_PY=py -3"
if not defined BASE_PY (
    echo [ERROR] Python 3.10 or newer was not found.
    echo Install it from https://www.python.org/downloads/ and tick
    echo "Add Python to PATH" during installation, then run this again.
    echo.
    pause
    exit /b 1
)

echo [*] First run: creating a virtual environment in .venv
if not exist "%CD%\.venv\Scripts\python.exe" !BASE_PY! -m venv "%CD%\.venv"
if not exist "%CD%\.venv\Scripts\python.exe" (
    echo [ERROR] Could not create the virtual environment in .venv
    pause
    exit /b 1
)
set PY_EXE="%CD%\.venv\Scripts\python.exe"
echo [*] Installing dependencies into .venv (about a minute, needs internet once)
!PY_EXE! -m pip install --disable-pip-version-check -r requirements.txt
if !errorlevel! neq 0 (
    echo.
    echo [ERROR] Installing the dependencies failed. Check the internet connection
    echo and run this again, or install by hand:
    echo     !PY_EXE! -m pip install -r requirements.txt
    pause
    exit /b 1
)

:python_ready
echo [*] Python: !PY_EXE!

REM The package is run from this folder without being installed.
set "PYTHONPATH=%CD%;!PYTHONPATH!"

REM -------------------------------------------------------------------------
REM Step 3: The ESP inference model ships in models\. Train only if missing.
REM -------------------------------------------------------------------------
if not exist "models\MANIFEST.sha256" (
    echo [*] No trained model in models\. Training one, about a minute...
    !PY_EXE! -m cipherguard.cli train
    echo.
)

REM -------------------------------------------------------------------------
REM Step 4: The port must be free. Whatever holds it is left alone: it may
REM not be CipherGuard, and ending another program is not this script's call.
REM -------------------------------------------------------------------------
netstat -ano 2>nul | findstr /r /c:":%PORT% .*LISTENING" >nul 2>nul
if !errorlevel! equ 0 (
    echo [ERROR] Port %PORT% is already in use.
    echo If another CipherGuard window is open, use that one or close it first.
    echo To use a different port instead, run:  launch_dashboard.bat --port 8001
    pause
    exit /b 1
)

REM The dashboard shows which links use weak cryptography, so it is served to
REM this machine only unless --lan is given, and --lan always sets a token.
REM It is never served to the network unauthenticated.
set "BIND_HOST=127.0.0.1"
if not defined LAN_MODE goto :bind_ready

set "BIND_HOST=0.0.0.0"
if defined CIPHERGUARD_TOKEN goto :token_ready
for /f "usebackq delims=" %%t in (`!PY_EXE! -c "import secrets; print(secrets.token_hex(16))"`) do set "CIPHERGUARD_TOKEN=%%t"
if not defined CIPHERGUARD_TOKEN (
    echo [ERROR] Could not generate an access token, so LAN mode was not started.
    echo         Run without --lan, or set CIPHERGUARD_TOKEN yourself and retry.
    pause
    exit /b 1
)
:token_ready

set "LAN_IP="
for /f "tokens=4" %%a in ('route print 0.0.0.0 2^>nul ^| findstr "\<0.0.0.0\>"') do (
    if not defined LAN_IP if not "%%a"=="0.0.0.0" set "LAN_IP=%%a"
)
:bind_ready

echo [*] Dashboard:    http://127.0.0.1:%PORT%/
if defined LAN_MODE (
    if defined LAN_IP (
        echo [*] On the LAN:   http://!LAN_IP!:%PORT%/
    ) else (
        echo [*] On the LAN:   http://YOUR-LAN-IP:%PORT%/   [see ipconfig for the address]
    )
    echo [*] Access token: !CIPHERGUARD_TOKEN!
    echo [*] Every browser, this one included, is asked for the token once.
    echo [*] The token crosses the network unencrypted. Use --lan on a network you trust.
) else (
    echo [*] Listening on this machine only. Run "launch_dashboard.bat --lan" to
    echo     serve other devices on the network, protected by an access token.
)
echo [*] Keep this window open. Press Ctrl+C to stop the server.
echo ======================================================================
echo.

if not defined CIPHERGUARD_NO_BROWSER start "" "http://127.0.0.1:%PORT%/"

REM In LAN mode the token is read from CIPHERGUARD_TOKEN.
!PY_EXE! -m cipherguard.cli serve --host !BIND_HOST! --port %PORT% !SERVE_ARGS!

REM Ctrl+C exits with 130 or STATUS_CONTROL_C_EXIT; anything else is a failure worth reading
if !errorlevel! neq 0 if !errorlevel! neq 130 if !errorlevel! neq -1073741510 (
    echo.
    echo [ERROR] The server stopped with exit code !errorlevel!
    pause
)
