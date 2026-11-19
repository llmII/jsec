@echo off
setlocal

for %%I in ("%~dp0..") do set "PREFIX=%%~fI"

set "JANET_PATH="
set "JANET_MODPATH="
set "JANET_HEADERPATH="
set "JANET_LIBPATH="
set "JANET_BINPATH="
set "JANET_BUILDPATH="
set "JANET_MANPATH="
set "JANET_TREE="

if not defined VCPKG_ROOT (
    for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v VCPKG_ROOT 2^>nul') do set "VCPKG_ROOT=%%B"
)
if defined OPENSSL_PREFIX goto :add_openssl_prefix
if defined VCPKG_ROOT goto :add_vcpkg_bin
goto :run_janet

:add_openssl_prefix
if exist "%OPENSSL_PREFIX%\bin" set "PATH=%OPENSSL_PREFIX%\bin;%PATH%"
goto :run_janet

:add_vcpkg_bin
if exist "%VCPKG_ROOT%\installed\x64-windows\bin" set "PATH=%VCPKG_ROOT%\installed\x64-windows\bin;%PATH%"

:run_janet
set "PATH=%PREFIX%\bin;%PATH%"

"%PREFIX%\bin\janet.exe" %*
exit /b %ERRORLEVEL%
