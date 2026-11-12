@echo off
rem NetPulse launcher. Double-click it to start NetPulse and open it in your browser.
rem
rem The first time, it makes a Python environment in the .venv folder beside it and
rem installs NetPulse into it, which needs the internet once. After that it only
rem starts NetPulse, and installs again by itself when NetPulse has been updated.
rem
rem Your data is netpulse.db in this folder. Close this window, or press Ctrl+C,
rem to stop NetPulse. Anything after the file name is passed on to NetPulse, so a
rem shortcut to "NetPulse.bat --local-only" starts it for this PC only.

setlocal
title NetPulse
cd /d "%~dp0"

set "HERE=%~dp0"
set "VENV_PY=%HERE%.venv\Scripts\python.exe"
set "STAMP=%HERE%.venv\netpulse-installed.toml"

if not exist "%HERE%pyproject.toml" goto :misplaced

rem Plain jumps, not ( ) blocks: inside a block, cmd reads %PYTHON% before the
rem block runs, so a value set in it would come through empty.
if exist "%VENV_PY%" goto :have_venv
call :find_python || goto :failed
echo Setting up NetPulse for the first time. This takes a minute and needs the internet once.
"%PYTHON%" -m venv "%HERE%.venv" || goto :failed
:have_venv

rem Installed already, from this very version? Then there is nothing to do.
fc /b "%HERE%pyproject.toml" "%STAMP%" >nul 2>&1 && goto :installed
echo Installing NetPulse and what it needs...
"%VENV_PY%" -m pip install --disable-pip-version-check --quiet --editable "%HERE%." || goto :failed
copy /y "%HERE%pyproject.toml" "%STAMP%" >nul
:installed

echo Starting NetPulse. Your browser opens when it is ready.
echo Keep this window open while you use NetPulse. Close it, or press Ctrl+C, to stop.
echo.
"%VENV_PY%" -m netpulse --db "%HERE%netpulse.db" --open %*
if errorlevel 1 goto :failed
exit /b 0

:find_python
rem The Python launcher first, then python on the PATH. Either must be 3.11 or newer.
set "PYTHON="
for %%P in (py python) do (
    if not defined PYTHON (
        %%P -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1 && set "PYTHON=%%P"
    )
)
if defined PYTHON exit /b 0
echo NetPulse needs Python 3.11 or newer, and this PC does not have it.
echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
echo then double-click NetPulse.bat again.
exit /b 1

:misplaced
echo This file has to stay in the NetPulse folder, next to pyproject.toml and src.
echo To start NetPulse from somewhere else, make a shortcut to it instead.

:failed
echo.
echo NetPulse stopped. The lines above say why.
pause
exit /b 1
