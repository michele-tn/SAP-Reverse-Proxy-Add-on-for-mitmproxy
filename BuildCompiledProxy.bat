@echo off
setlocal
cd /d "%~dp0"

call "%~dp0SetupMitmProxy.bat"
if errorlevel 1 exit /b 1

".venv\Scripts\python.exe" -m pip install --upgrade pyinstaller
if errorlevel 1 exit /b 1

if exist "build_compiled" rmdir /s /q "build_compiled"
if exist "dist_compiled" rmdir /s /q "dist_compiled"

".venv\Scripts\pyinstaller.exe" ^
  --noconfirm ^
  --clean ^
  --onedir ^
  --name GBMitmProxy ^
  --distpath dist_compiled ^
  --workpath build_compiled ^
  --add-data "sap_reverse_proxy_mitm.py;." ^
  --collect-all mitmproxy ^
  --collect-all mitmproxy_rs ^
  --collect-all aioquic ^
  --collect-all cryptography ^
  --collect-all OpenSSL ^
  compiled_proxy_launcher.py

if errorlevel 1 exit /b 1

copy /y "StartCompiledProxy.bat" "dist_compiled\GBMitmProxy\" >nul
copy /y "README.md" "dist_compiled\GBMitmProxy\" >nul
copy /y "sap_reverse_proxy_mitm.py" "dist_compiled\GBMitmProxy\" >nul

echo.
echo Build completed:
echo %CD%\dist_compiled\GBMitmProxy\GBMitmProxy.exe
