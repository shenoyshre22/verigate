
@echo off
setlocal

cd /d "%~dp0"

set "SERVICE=%~dp0fingerprint-service"
set "EXE=%SERVICE%\bin\FingerprintService.exe"
set "BUILD=%SERVICE%\build.ps1"

echo ========================================
echo   HID BIOMETRIC AUTH - MFS100
echo ========================================
echo.

echo Building latest source code...

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%BUILD%"

if errorlevel 1 (
    echo.
    echo BUILD FAILED. Application not launched.
    pause
    exit /b 1
)

if not exist "%EXE%" (
    echo ERROR: Executable was not generated.
    pause
    exit /b 1
)

echo.
echo Launching fingerprint service...
echo.

"%EXE%"

set "RESULT=%ERRORLEVEL%"

echo.
echo Fingerprint service exited with code %RESULT%.
pause

exit /b %RESULT%

