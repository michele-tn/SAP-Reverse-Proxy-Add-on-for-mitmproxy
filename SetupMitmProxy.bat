@echo off
setlocal
cd /d "%~dp0"

set "VENV_DIR=%~dp0.venv"
set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"

if exist "%PYTHON_EXE%" (
  "%PYTHON_EXE%" -c "import sys" >nul 2>&1
  if errorlevel 1 (
    echo Existing virtual environment is invalid: removing and recreating it.
    rmdir /s /q "%VENV_DIR%"
  )
)

if not exist "%PYTHON_EXE%" (
  py -3 -m venv "%VENV_DIR%" >nul 2>&1
  if errorlevel 1 (
    python -m venv "%VENV_DIR%"
  )
  if errorlevel 1 (
    echo Failed to create the virtual environment.
    echo Install Python 3 or make sure py.exe or python.exe is available.
    exit /b 1
  )
)

"%PYTHON_EXE%" -m pip install --upgrade pip
if errorlevel 1 exit /b 1

"%PYTHON_EXE%" -m pip install -r requirements.txt
if errorlevel 1 exit /b 1

"%PYTHON_EXE%" -c "import mitmproxy" >nul 2>&1
if errorlevel 1 (
  echo mitmproxy is not installed in the local environment.
  exit /b 1
)

echo.
echo Setup completed.
echo Start the proxy with StartMitmProxy.bat
