@echo off
setlocal enabledelayedexpansion
title lancer-dnsx Build

REM ============================================================
REM  build.bat -- Build lancer-dnsx.exe for Windows
REM  Output: build\lancer-dnsx.exe
REM
REM  Requirements:
REM    - Rust / Cargo   https://rustup.rs
REM    - Visual C++ Build Tools (2019/2022)
REM ============================================================

set "REPO=%~dp0"
set "REPO=%REPO:~0,-1%"
set "BUILD=%REPO%\build"
set "BIN=lancer-dnsx.exe"

echo.
echo  ================================================
echo    lancer-dnsx  Build
echo  ================================================
echo.
echo  Repo   : %REPO%
echo  Output : %BUILD%\%BIN%
echo.

REM Locate cargo
where cargo >nul 2>&1
if errorlevel 1 (
    set "CARGO=%USERPROFILE%\.cargo\bin\cargo.exe"
    if not exist "!CARGO!" (
        echo  ERROR: cargo not found.
        echo  Install Rust from https://rustup.rs then re-run.
        pause
        exit /b 1
    )
) else (
    set "CARGO=cargo"
)

echo  [1/2]  Building release binary...
"!CARGO!" build --release
if errorlevel 1 (
    echo  ERROR: cargo build failed
    pause
    exit /b 1
)

echo  [2/2]  Copying to build\...
if not exist "%BUILD%" mkdir "%BUILD%"
copy /Y "%REPO%\target\release\%BIN%" "%BUILD%\" >nul
if errorlevel 1 (
    echo  ERROR: %BIN% not found in target\release
    pause
    exit /b 1
)

echo.
echo  ================================================
echo    Done!  Binary ready:
echo.
echo    %BUILD%\%BIN%
echo  ================================================
echo.
pause
endlocal
