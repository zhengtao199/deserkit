@echo off
chcp 65001 >nul
cd /d "%~dp0"
title deserkit GUI (do not close)
setlocal enabledelayedexpansion

rem ============================================================
rem  deserkit launcher - portable, no machine-specific paths
rem  NOTE: this file MUST be CRLF (Windows) + plain ASCII.
rem        cmd.exe mis-parses multi-line for/ do blocks with LF
rem        line endings, and chcp 65001 shifts byte offsets when
rem        non-ASCII bytes are present. Keep it ASCII-only.
rem ============================================================
set "PY="

rem (1) python / python3 on PATH, version >= 3.8
for %%C in (python python3) do (
  if not defined PY (
    where %%C >nul 2>nul
    if not errorlevel 1 (
      %%C -c "import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>nul
      if not errorlevel 1 set "PY=%%C"
    )
  )
)

rem (2) Windows Python launcher: py -3
if not defined PY (
  where py >nul 2>nul
  if not errorlevel 1 (
    py -3 -c "import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>nul
    if not errorlevel 1 set "PY=py -3"
  )
)

rem (3) common install locations: ...\Python3*\python.exe
if not defined PY (
  for %%R in ("%LOCALAPPDATA%\Programs\Python" "%ProgramFiles%\Python" "%ProgramFiles(x86)%\Python" "%SystemDrive%\Python" "%USERPROFILE%\AppData\Local\Programs\Python" "C:\Python") do (
    if not defined PY (
      for /d %%D in ("%%~R\Python3*") do (
        if exist "%%~D\python.exe" (
          "%%~D\python.exe" -c "import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>nul
          if not errorlevel 1 set PY="%%~D\python.exe"
        )
      )
    )
  )
)

if not defined PY goto NOPY

echo [*] Python: !PY!
echo [*] Starting deserkit GUI ...
echo     If a port is busy or blocked, the tool picks the next free one.
echo     Watch the banner below for the ACTUAL port to use.
echo     If the target cannot reach you, run the firewall script below
echo     as Administrator to allow inbound traffic:
for %%F in (*.bat) do if /I not "%%~nxF"=="start-gui.bat" echo       %%~nxF
echo     Chinese docs: README.md
echo.
!PY! gui_server.py
echo.
echo [STOP] Server exited. If you saw "[auto-fallback]" above, use the
echo     actual address/port printed there.
pause
exit /b 0

:NOPY
echo ============================================================
echo  [ERR] Python 3.8+ was not found on this machine.
echo.
echo    Download: https://www.python.org/downloads/windows/
echo         (mirror: https://mirrors.huaweicloud.com/python/)
echo    During setup, tick "Add python.exe to PATH".
echo    Already installed but still failing? Add the folder that
echo    contains python.exe to the system PATH, then run this again.
echo ============================================================
pause
exit /b 1
