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
set "JANET_WINDOWS_PREFIX="
set "JANET_JPM_CONFIG="
set "JPM_BOOTSTRAP_CONFIG="

if not defined VCPKG_ROOT (
    for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v VCPKG_ROOT 2^>nul') do set "VCPKG_ROOT=%%B"
)

where cl.exe >nul 2>&1
if errorlevel 1 goto :need_msvc
if not defined INCLUDE goto :need_msvc
goto :msvc_ready

:need_msvc
set "VCVARS="
call :probe_vs "%ProgramFiles(x86)%"
if not defined VCVARS call :probe_vs "%ProgramFiles%"
if not defined VCVARS call :probe_vswhere
if not defined VCVARS goto :msvc_ready

set "SAVED_PREFIX=%PREFIX%"
set "SAVED_VCPKG=%VCPKG_ROOT%"
set "SAVED_OPENSSL=%OPENSSL_PREFIX%"
call "%VCVARS%" x64 >nul 2>&1
set "PREFIX=%SAVED_PREFIX%"
if defined SAVED_VCPKG set "VCPKG_ROOT=%SAVED_VCPKG%"
if defined SAVED_OPENSSL set "OPENSSL_PREFIX=%SAVED_OPENSSL%"

:msvc_ready
if defined OPENSSL_PREFIX goto :add_openssl_prefix
if defined VCPKG_ROOT goto :add_vcpkg_bin
goto :run_jpm

:add_openssl_prefix
if exist "%OPENSSL_PREFIX%\bin" set "PATH=%OPENSSL_PREFIX%\bin;%PATH%"
goto :run_jpm

:add_vcpkg_bin
if exist "%VCPKG_ROOT%\installed\x64-windows\bin" set "PATH=%VCPKG_ROOT%\installed\x64-windows\bin;%PATH%"

:run_jpm
set "PATH=%PREFIX%\bin;%PATH%"

"%PREFIX%\bin\janet.exe" "%PREFIX%\libexec\jpm" %*
exit /b %ERRORLEVEL%

:probe_vs
if "%~1"=="" exit /b 0
setlocal EnableDelayedExpansion
set "_VSROOT=%~1"
set "_FOUND="
for %%Y in (2022 2019) do (
    for %%E in (BuildTools Community Professional Enterprise) do (
        if not defined _FOUND (
            if exist "!_VSROOT!\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvarsall.bat" (
                set "_FOUND=!_VSROOT!\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvarsall.bat"
            )
        )
    )
)
endlocal & set "VCVARS=%_FOUND%"
exit /b 0

:probe_vswhere
set "VSW=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSW%" exit /b 0
set "VSW_FOUND="
for /f "usebackq delims=" %%I in (`powershell -NoProfile -Command "& $env:VSW -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath"`) do (
    if not defined VSW_FOUND if exist "%%~I\VC\Auxiliary\Build\vcvarsall.bat" set "VSW_FOUND=%%~I\VC\Auxiliary\Build\vcvarsall.bat"
)
if defined VSW_FOUND set "VCVARS=%VSW_FOUND%"
exit /b 0
