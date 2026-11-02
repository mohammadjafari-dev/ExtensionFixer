@echo off
title Build ExtensionFixer.exe
echo ================================================================
echo   Building ExtensionFixer.exe  (single file + icon)
echo ================================================================
echo.
echo Run this script from the SAME folder that contains:
echo   - filetype_gui.py
echo   - filetype_core.py
echo   - assets\icon.ico
echo.

where python >nul 2>&1
if errorlevel 1 goto NO_PYTHON

if not exist "filetype_gui.py"  goto NO_GUI_FILE
if not exist "filetype_core.py" goto NO_CORE_FILE
if not exist "assets\icon.ico"  goto NO_ICON

echo [1/3] Installing PyInstaller (version 6.x, without touching system pip) ...
python -m pip install --upgrade "pyinstaller>=6.6,<7"
if errorlevel 1 goto PIP_FAILED

echo.
echo [2/3] Cleaning previous build output (if any) ...
if exist "build" rd /s /q "build"
if exist "dist" rd /s /q "dist"
if exist "ExtensionFixer.spec" del /q "ExtensionFixer.spec"

echo.
echo [3/3] Building the exe (this can take a minute or two) ...
python -m PyInstaller --noconfirm --onefile --windowed --name ExtensionFixer --icon "assets\icon.ico" --add-data "assets;assets" filetype_gui.py

echo.
if exist "dist\ExtensionFixer.exe" goto SUCCESS
goto BUILD_FAILED

:SUCCESS
echo ================================================================
echo   SUCCESS!
echo   Your executable is at:  dist\ExtensionFixer.exe
echo   Put it in the GitHub Release (not inside the repo).
echo   SHA-256 checksum to publish with the Release:
certutil -hashfile "dist\ExtensionFixer.exe" SHA256
echo ================================================================
goto END

:NO_PYTHON
echo [ERROR] Python was not found in PATH.
echo Install it from https://www.python.org/downloads/
echo During install, check "Add python.exe to PATH".
goto END

:NO_GUI_FILE
echo [ERROR] filetype_gui.py was not found in this folder.
goto END

:NO_CORE_FILE
echo [ERROR] filetype_core.py was not found in this folder.
goto END

:NO_ICON
echo [ERROR] assets\icon.ico was not found in this folder.
goto END

:PIP_FAILED
echo [ERROR] Failed to install PyInstaller. Check your internet connection.
goto END

:BUILD_FAILED
echo ================================================================
echo   [ERROR] Build did not produce an exe. Check the messages above.
echo ================================================================
goto END

:END
pause
