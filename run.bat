@echo off
title ExtensionFixer - Run
cd /d "%~dp0"

if not exist "filetype_gui.py" goto NO_GUI_FILE

rem ------------------------------------------------------------------
rem Find a real Python (3.8+). The "py" launcher is tried first, then
rem "python". The Microsoft Store python stub prints a message and
rem exits with an error, so it is rejected by the "-c" check.
rem ------------------------------------------------------------------
set "PYCMD="

where py >nul 2>&1
if not errorlevel 1 (
    py -3 -c "import sys" >nul 2>&1
    if not errorlevel 1 set "PYCMD=py -3"
)

if not defined PYCMD (
    where python >nul 2>&1
    if not errorlevel 1 (
        python -c "import sys" >nul 2>&1
        if not errorlevel 1 set "PYCMD=python"
    )
)

if not defined PYCMD goto NO_PYTHON

echo Starting ExtensionFixer ...
%PYCMD% filetype_gui.py
if errorlevel 1 pause
goto END

:NO_PYTHON
echo [ERROR] Python (3.8+) was not found.
echo NOTE: if only the Microsoft Store stub exists, this script will
echo not accept it. Install real Python from https://www.python.org/downloads/
echo and check "Add python.exe to PATH" during installation.
pause
goto END

:NO_GUI_FILE
echo [ERROR] filetype_gui.py was not found in this folder.
echo Run this script from the folder that contains the program files.
pause
goto END

:END
