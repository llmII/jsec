@echo off
setlocal EnableExtensions

rem ============================================================================
rem JSEC Hermetic In-Tree Toolchain Seed Wrapper (Windows / MSVC)
rem ============================================================================
rem Minimal batch bootstrap: initializes MSVC x64, ensures a seed janet.exe
rem exists in .work\seed\janet.exe, and delegates all toolchain management to
rem scripts\bootstrap-toolchain.janet.
rem ============================================================================

set "SEED_JANET_REV=8b6d56edae8c1eb5ae19b024087a065b6918b9ef"
if not defined JANET_URL set "JANET_URL=https://github.com/janet-lang/janet.git"

for %%I in ("%~dp0.") do set "SCRIPT_DIR=%%~fI"
for %%I in ("%SCRIPT_DIR%\..") do set "ROOT_DIR=%%~fI"
set "WORK_DIR=%ROOT_DIR%\.work"
set "SEED_DIR=%WORK_DIR%\seed"
set "SEED_JANET=%SEED_DIR%\janet.exe"
set "JANET_SRC_DIR=%WORK_DIR%\src\janet"

where cl.exe >nul 2>&1
if errorlevel 1 goto :init_msvc
if not defined INCLUDE goto :init_msvc
goto :msvc_ok

:init_msvc
set "VCVARS="
for %%R in ("%ProgramFiles(x86)%" "%ProgramFiles%") do (
    for %%Y in (2022 2019) do (
        for %%E in (BuildTools Community Professional Enterprise) do (
            if not defined VCVARS if exist "%%~R\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvarsall.bat" (
                set "VCVARS=%%~R\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvarsall.bat"
            )
        )
    )
)
if not defined VCVARS (
    echo ERROR: Visual Studio C++ x64 build tools ^(vcvarsall.bat^) not found.>&2
    exit /b 1
)
call "%VCVARS%" x64 >nul || (
    echo ERROR: failed to initialize MSVC x64 environment.>&2
    exit /b 1
)

:msvc_ok
if exist "%SEED_JANET%" goto :run_manager
if not exist "%SEED_DIR%" mkdir "%SEED_DIR%"
if exist "%WORK_DIR%\bin\janet.exe" (
    copy /Y "%WORK_DIR%\bin\janet.exe" "%SEED_JANET%" >nul && goto :run_manager
)

echo ==^> Building seed Janet into %SEED_JANET%...
if not exist "%JANET_SRC_DIR%\src\core\ev.c" (
    if exist "%JANET_SRC_DIR%" rd /s /q "%JANET_SRC_DIR%"
    mkdir "%JANET_SRC_DIR%"
    if defined JANET_SRC if exist "%JANET_SRC%\.git" (
        git -C "%JANET_SRC%" archive "%SEED_JANET_REV%" | tar -xf - -C "%JANET_SRC_DIR%" || exit /b 1
    ) else (
        git clone "%JANET_URL%" "%JANET_SRC_DIR%" >nul 2>&1 || exit /b 1
        git -C "%JANET_SRC_DIR%" checkout --quiet "%SEED_JANET_REV%" || exit /b 1
    )
    > "%JANET_SRC_DIR%\.jsec-rev" echo %SEED_JANET_REV%
)

pushd "%JANET_SRC_DIR%" >nul
if not exist "build\boot" mkdir "build\boot"
if not exist "build\c" mkdir "build\c"
set "J_CFLAGS=/nologo /Isrc\include /Isrc\conf /c /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /MD"
for %%F in (src\core\*.c src\boot\*.c) do (
    cl %J_CFLAGS% /DJANET_BOOTSTRAP /Fobuild\boot\%%~nF.obj "%%F" >nul || (popd & exit /b 1)
)
link /nologo /OUT:build\janet_boot.exe build\boot\*.obj >nul || (popd & exit /b 1)
build\janet_boot.exe . > build\c\janet.c || (popd & exit /b 1)
cl %J_CFLAGS% /Fobuild\janet.obj build\c\janet.c >nul || (popd & exit /b 1)
cl %J_CFLAGS% /Fobuild\shell.obj src\mainclient\shell.c >nul || (popd & exit /b 1)
link /nologo /OUT:"%SEED_JANET%" build\janet.obj build\shell.obj >nul || (popd & exit /b 1)
popd >nul

:run_manager
"%SEED_JANET%" "%SCRIPT_DIR%\bootstrap-toolchain.janet" %*
exit /b %ERRORLEVEL%
