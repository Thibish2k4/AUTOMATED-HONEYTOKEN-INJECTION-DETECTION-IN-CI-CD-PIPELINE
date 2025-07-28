@echo off
echo ========================================
echo 🍯 Windows Honeytoken Tool - Live Demo
echo ========================================
echo.

echo 📋 Prerequisites Check...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.8+ and try again.
    pause
    exit /b 1
)

echo ✅ Python found
echo.

echo 📦 Installing dependencies...
pip install -r requirements.txt >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Warning: Some dependencies may not have installed correctly
)

pip install -r web_requirements.txt >nul 2>&1
echo ✅ Dependencies installed
echo.

echo 🎬 Starting comprehensive demo...
echo ========================================
echo.

echo 1. Initializing configuration...
python src/windows_cli.py init
echo.

echo 2. Running comprehensive demo...
python src/windows_cli.py demo
echo.

echo 3. Generating test report...
python src/windows_cli.py test
echo.

echo 4. Exporting configuration...
python src/windows_cli.py export --output demo_export.json
echo.

echo 5. Starting web dashboard (will open in browser)...
echo    Access at: http://localhost:5000
echo    Press Ctrl+C to stop the web server
echo.

start "" "http://localhost:5000"
python src/windows_cli.py web

echo.
echo ========================================
echo 🎉 Demo completed successfully!
echo ========================================
echo.
echo Next steps:
echo • Review the generated reports
echo • Check demo_export.json for configuration
echo • Explore the web dashboard features
echo • Try: python src/windows_cli.py --help
echo.
pause
