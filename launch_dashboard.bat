@echo off
setlocal enabledelayedexpansion
title CipherGuard

REM UTF-8 console output, for network names and symbols in the server's log
chcp 65001 >nul 2>nul
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

REM -------------------------------------------------------------------------
REM Arguments:
REM   --lan         serves other devices on the network, behind a token.
REM   --port N      changes the listening port (default: 8000).
REM   --no-browser  suppresses opening the browser automatically.
REM   --help, -h    prints usage and exits.
REM Without --lan the dashboard listens on loopback (127.0.0.1) only.
REM Everything else is passed through to "cipherguard serve".
REM -------------------------------------------------------------------------
set "LAN_MODE="
set "PORT=8000"
set "SERVE_ARGS="

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--help" goto :show_help
if /i "%~1"=="-h" goto :show_help
if /i "%~1"=="/?" goto :show_help
if /i "%~1"=="--no-browser" (
    set "CIPHERGUARD_NO_BROWSER=1"
) else if /i "%~1"=="--lan" (
    set "LAN_MODE=1"
) else if /i "%~1"=="--port" (
    if "%~2"=="" (
        echo [ERROR] --port requires a port number argument.
        (call) & exit /b 1
    )
    set "PORT_ARG=%~2"
    set "PORT_NON_DIGIT="
    for /f "delims=0123456789" %%a in ("!PORT_ARG!") do set "PORT_NON_DIGIT=%%a"
    if defined PORT_NON_DIGIT (
        echo [ERROR] Invalid port "!PORT_ARG!": port must be a numeric integer.
        (call) & exit /b 1
    )
    if !PORT_ARG! lss 1 (
        echo [ERROR] Invalid port "!PORT_ARG!": port must be between 1 and 65535.
        (call) & exit /b 1
    )
    if !PORT_ARG! gtr 65535 (
        echo [ERROR] Invalid port "!PORT_ARG!": port must be between 1 and 65535.
        (call) & exit /b 1
    )
    set "PORT=!PORT_ARG!"
    shift
) else (
    set "SERVE_ARGS=!SERVE_ARGS! %1"
)
shift
goto :parse_args

:show_help
echo Usage: launch_dashboard.bat [OPTIONS]
echo.
echo Launch the CipherGuard dashboard server and open it in your default browser.
echo.
echo Options:
echo   --port PORT       Set the port to listen on (default: 8000).
echo   --lan             Serve other devices on the local network (requires access token).
echo   --no-browser      Do not open the dashboard in a browser automatically.
echo   --help, -h        Show this help message and exit.
echo.
echo Environment variables:
echo   PORT                    Default port if --port is omitted.
echo   CIPHERGUARD_NO_BROWSER  Set to 1 to suppress opening the browser.
echo   CIPHERGUARD_TOKEN       Access token for --lan authentication (generated if unset).
echo.
exit /b 0

:args_done
cls

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
REM Probes every top-level package required by reading requirements.txt.
REM PY_EXE holds the whole command, quoted where it is a path, so it is
REM always used as  !PY_EXE! -m ...
REM -------------------------------------------------------------------------
set "PY_EXE="
set "PROBE_CMD=import importlib, re, sys; m={'scikit-learn':'sklearn'}; [sys.exit(1) if p=='python-multipart' and not (__import__('importlib.util').util.find_spec('multipart') or __import__('importlib.util').util.find_spec('python_multipart')) else importlib.import_module(m.get(p, p.replace('-','_'))) for p in [re.split(r'[<=>~;\s]', l.split('#')[0].strip())[0].lower() for l in open('requirements.txt', encoding='utf-8')] if p]"

if defined VIRTUAL_ENV if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
    "%VIRTUAL_ENV%\Scripts\python.exe" -c "!PROBE_CMD!" >nul 2>nul && set PY_EXE="%VIRTUAL_ENV%\Scripts\python.exe"
)
if defined PY_EXE goto :python_ready

for %%d in (.venv venv) do (
    if not defined PY_EXE if exist "%CD%\%%d\Scripts\python.exe" (
        "%CD%\%%d\Scripts\python.exe" -c "!PROBE_CMD!" >nul 2>nul && set PY_EXE="%CD%\%%d\Scripts\python.exe"
    )
)
if defined PY_EXE goto :python_ready

python -c "!PROBE_CMD!" >nul 2>nul && set "PY_EXE=python"
if defined PY_EXE goto :python_ready

py -3 -c "!PROBE_CMD!" >nul 2>nul && set "PY_EXE=py -3"
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
set "REQ_FILE=requirements.txt"
if exist "requirements.lock" set "REQ_FILE=requirements.lock"
echo [*] Installing dependencies into .venv from !REQ_FILE! (about a minute, needs internet once)
!PY_EXE! -m pip install --disable-pip-version-check -r !REQ_FILE!
if !errorlevel! neq 0 (
    echo.
    echo [ERROR] Installing the dependencies failed. Check the internet connection
    echo and run this again, or install by hand:
    echo     !PY_EXE! -m pip install -r !REQ_FILE!
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
    if !errorlevel! neq 0 (
        echo.
        echo [ERROR] Training the inference model failed with exit code !errorlevel!.
        pause
        exit /b 1
    )
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

if not defined CIPHERGUARD_NO_BROWSER (
    set "WAIT_CMD=exec('import time, urllib.request, urllib.error, os, sys\nurl = \"http://127.0.0.1:%PORT%/\"\nfor _ in range(60):\n try:\n  with urllib.request.urlopen(url, timeout=1):\n   os.startfile(url); sys.exit(0)\n except urllib.error.HTTPError:\n  os.startfile(url); sys.exit(0)\n except Exception:\n  time.sleep(0.5)\nsys.exit(0)')"
    start "" /b !PY_EXE! -c "!WAIT_CMD!"
)

REM In LAN mode the token is read from CIPHERGUARD_TOKEN.
!PY_EXE! -m cipherguard.cli serve --host !BIND_HOST! --port %PORT% !SERVE_ARGS!

REM Ctrl+C exits with 130 or STATUS_CONTROL_C_EXIT; anything else is a failure worth reading
if !errorlevel! neq 0 if !errorlevel! neq 130 if !errorlevel! neq -1073741510 (
    echo.
    echo [ERROR] The server stopped with exit code !errorlevel!
    pause
)
