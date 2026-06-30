@echo off
setlocal
cd /d "%~dp0"

set "VENV_DIR=%~dp0.venv"
set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"

if "%GB_MITM_LOCAL_ORIGIN%"=="" set "GB_MITM_LOCAL_ORIGIN=https://localhost:1337"
if "%GB_MITM_LOCAL_HOSTNAMES%"=="" set "GB_MITM_LOCAL_HOSTNAMES=localhost,127.0.0.1"
if "%GB_MITM_LISTEN_HOST%"=="" set "GB_MITM_LISTEN_HOST=0.0.0.0"
if "%GB_MITM_LISTEN_PORT%"=="" set "GB_MITM_LISTEN_PORT=1337"
if "%GB_MITM_S4_UPSTREAM%"=="" set "GB_MITM_S4_UPSTREAM=https://s4.example.invalid/"
if "%GB_MITM_IDP_UPSTREAM%"=="" set "GB_MITM_IDP_UPSTREAM=https://ias-cloud.example.invalid/"
if "%GB_MITM_IDP_OD_UPSTREAM%"=="" set "GB_MITM_IDP_OD_UPSTREAM=https://ias-ondemand.example.invalid/"

if not exist "%PYTHON_EXE%" (
  echo Local Python environment not found: running setup.
  call "%~dp0SetupMitmProxy.bat"
  if errorlevel 1 exit /b 1
)

"%PYTHON_EXE%" -c "import mitmproxy" >nul 2>&1
if errorlevel 1 (
  echo Local Python environment is invalid or mitmproxy is missing: running setup.
  call "%~dp0SetupMitmProxy.bat"
  if errorlevel 1 exit /b 1
)

set "CERT_ARGS="
if not "%GB_MITM_CERTS%"=="" set "CERT_ARGS=%GB_MITM_CERTS%"

"%PYTHON_EXE%" "%~dp0run_mitmdump.py" --set http2=false --set connection_strategy=lazy --listen-host "%GB_MITM_LISTEN_HOST%" --listen-port "%GB_MITM_LISTEN_PORT%" --mode reverse:%GB_MITM_S4_UPSTREAM% --ssl-insecure %CERT_ARGS% -s sap_reverse_proxy_mitm.py
