@echo off
echo 🍯 Windows Honeytoken Tool Setup
echo ================================

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.8+ first.
    exit /b 1
)

echo ✅ Python found

REM Create virtual environment
if not exist "venv" (
    echo 📦 Creating virtual environment...
    python -m venv venv
)

echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat

echo 📥 Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt

echo 📁 Creating directories...
if not exist "config" mkdir config
if not exist "scripts" mkdir scripts  
if not exist "tests" mkdir tests
if not exist "C:\temp" mkdir C:\temp

echo 🔧 Installing package...
pip install -e .

echo ✅ Setup complete!
echo.
echo Next steps:
echo 1. Open this folder in VS Code
echo 2. Select Python interpreter: venv\Scripts\python.exe
echo 3. Press F5 to run or use terminal: python src\windows_cli.py --help
pause
