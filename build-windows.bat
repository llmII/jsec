@echo off
REM Windows build script for jsec
REM Requires: Visual Studio 2022 Build Tools, vcpkg with OpenSSL installed
REM
REM Prerequisites:
REM   - Janet installed and in PATH  
REM   - jpm properly configured (jpm show-paths should show correct libpath)
REM   - VCPKG_ROOT environment variable set to vcpkg installation
REM   - OpenSSL installed via: vcpkg install openssl:x64-windows
REM
REM IMPORTANT: When running jsec, ensure vcpkg OpenSSL DLLs are in PATH:
REM   set PATH=%VCPKG_ROOT%\installed\x64-windows\bin;%PATH%

REM Change to the directory where this batch file is located
cd /d "%~dp0"

REM Load VCPKG_ROOT from user environment if not set in current session
if not defined VCPKG_ROOT (
    for /f "tokens=2*" %%a in ('reg query HKCU\Environment /v VCPKG_ROOT 2^>nul') do set "VCPKG_ROOT=%%b"
)

REM Verify VCPKG_ROOT is set
if not defined VCPKG_ROOT (
    echo ERROR: VCPKG_ROOT environment variable not set
    echo Please set it with: setx VCPKG_ROOT "path\to\vcpkg"
    exit /b 1
)

REM Save VCPKG_ROOT before vcvarsall (it may reset environment)
set "SAVED_VCPKG_ROOT=%VCPKG_ROOT%"

REM Set up MSVC environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64

REM Restore VCPKG_ROOT after vcvarsall
set "VCPKG_ROOT=%SAVED_VCPKG_ROOT%"

REM Add vcpkg OpenSSL DLLs to PATH for runtime loading
set "PATH=%VCPKG_ROOT%\installed\x64-windows\bin;%PATH%"

REM Build with jpm
jpm build
jpm install

echo.
echo Build complete! To run Janet with jsec, ensure OpenSSL DLLs are in PATH:
echo   set PATH=%%VCPKG_ROOT%%\installed\x64-windows\bin;%%PATH%%
