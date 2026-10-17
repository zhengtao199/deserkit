@echo off
chcp 65001 >nul
cd /d "%~dp0"
title deserkit - allow lab ports inbound
setlocal enabledelayedexpansion

rem ============================================================
rem  deserkit: allow lab ports inbound (needs Administrator)
rem
rem  Usage:
rem    no argument      -> allow 1389,8000,4444 (the defaults)
rem    with ports       -> allow the ports you pass, e.g. 1401 8912
rem
rem  With no argument it first asks the running deserkit GUI
rem  (http://127.0.0.1:8899/api/env) for the ports ACTUALLY in
rem  use, because the tool now auto-falls-back to the next free port
rem  when the default one is busy (WinError 10048) or blocked by the
rem  Windows reserved port range (WinError 10013).
rem  If the GUI is not running, or python is missing, it silently
rem  falls back to the default list above.
rem
rem  DESIGN NOTE (do not "fix" this back):
rem    We intentionally do NOT use SO_EXCLUSIVEADDRUSE on Windows.
rem    It would stop a just-closed listening port from being rebound
rem    while residual connections are in TIME_WAIT, which breaks the
rem    normal workflow of stopping and restarting the reverse-shell
rem    listener. Instead, bind_tcp_server()/bind_socket() in
rem    gui_server.py probe for a foreign listener BEFORE binding
rem    (using the pid in /api/status to tell our own instance apart),
rem    so an occupied port always falls back to the next free one.
rem
rem  IMPORTANT: this file MUST stay CRLF + plain ASCII.
rem    - cmd.exe mis-parses multi-line "for ... do (...)" blocks when the
rem      line endings are LF (you get "xxx is not recognized ...").
rem    - chcp 65001 shifts byte offsets if non-ASCII bytes are present,
rem      which can turn an "echo" line into a fake command.
rem  Any Chinese text is printed at run time via an ASCII wildcard.
rem ============================================================

set "RULE=deserkit-lab"
set "PORTS="
set "PYCMD="
set "TMPF=%TEMP%\deserkit_ports.txt"

rem --- (1) explicit ports from the command line win ----------------
for %%P in (%*) do (
  if defined PORTS (set "PORTS=!PORTS!,%%P") else (set "PORTS=%%P")
)

rem --- (2) no argument: ask the running GUI (port 8899) for the real ports
if defined PORTS goto HAVE_PORTS
call :FIND_PY
if not defined PYCMD goto HAVE_PORTS
if exist "%TMPF%" del "%TMPF%" >nul 2>nul
!PYCMD! -c "import json,urllib.request as u;j=json.load(u.urlopen('http://127.0.0.1:8899/api/env',timeout=3));print(','.join(sorted(str(v['port']) for v in j.get('ports',{}).values())))" > "%TMPF%" 2>nul
if exist "%TMPF%" set /p PORTS=<"%TMPF%"
if exist "%TMPF%" del "%TMPF%" >nul 2>nul

:HAVE_PORTS
rem --- (3) last resort: the classic default lab ports -------------
if not defined PORTS set "PORTS=1389,8000,4444"

echo [*] script: see the .bat file named with the port keyword below
for %%F in (*.bat) do if /I not "%%~nxF"=="start-gui.bat" echo     found: %%~nxF
echo [*] allowing inbound TCP ports: !PORTS!
echo.

netsh advfirewall firewall delete rule name="!RULE!" >nul 2>nul
netsh advfirewall firewall add rule name="!RULE!" dir=in action=allow protocol=TCP localport=!PORTS!

if errorlevel 1 goto FAIL

echo [+] OK. The ports above are now allowed inbound.
echo     Remove later with:
echo       netsh advfirewall firewall delete rule name="!RULE!"
goto DONE

:FAIL
echo.
echo [ERR] FAILED. Right-click this file and choose
echo       "Run as administrator", then run it again.
echo       If you already are admin, check that the Windows
echo       Firewall service is running.

:DONE
echo.
echo Lab ports: 1389=LDAP/JNDI  8000=HTTP codebase/callback  4444=reverse shell
pause
exit /b 0

rem ==== find a working python: PATH first, then py launcher, then common paths ====
:FIND_PY
set "PYCMD="
where python >nul 2>nul
if not errorlevel 1 (
  python -c "import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>nul
  if not errorlevel 1 (
    set "PYCMD=python"
    goto :eof
  )
)
where python3 >nul 2>nul
if not errorlevel 1 (
  python3 -c "import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>nul
  if not errorlevel 1 (
    set "PYCMD=python3"
    goto :eof
  )
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -c "import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>nul
  if not errorlevel 1 (
    set "PYCMD=py -3"
    goto :eof
  )
)
goto :eof
