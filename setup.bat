@echo off
echo === OrphanGuard Setup ===
echo.

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: Python not found. Install Python 3.10+ from python.org
    pause
    exit /b 1
)

echo Creating virtual environment...
python -m venv "%~dp0venv"

echo Installing dependencies...
call "%~dp0venv\Scripts\activate.bat"
pip install -r "%~dp0requirements.txt"

echo.
echo Setup complete! Run 'run.bat' to start OrphanGuard.
pause
