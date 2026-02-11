@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Clean up
if exist "%~dp0temp_out" rmdir /s /q "%~dp0temp_out"
if exist "%~dp0out.txt" del "%~dp0out.txt"
mkdir "%~dp0temp_out"

REM Run filemon
"%~dp0filemon_commandline_run.exe" "%~dp0out.txt" "%~dp0file_workload.exe" "%~dp0temp_out"

REM Check results
set PASS=0
set FAIL=0
set TOTAL=0
for %%f in ("%~dp0temp_out\*") do (
    set /a TOTAL+=1
    findstr /c:"%%~nxf" "%~dp0out.txt" >nul 2>&1
    if errorlevel 1 (
        echo MISS: %%~nxf
        set /a FAIL+=1
    ) else (
        set /a PASS+=1
    )
)

echo.
if !TOTAL! equ 0 (
    echo ERROR: No files found in temp_out - workload may have failed
    exit /b 1
)
echo PASS: !PASS!  FAIL: !FAIL!  (out of !TOTAL! files)
if !FAIL! gtr 0 (
    echo TEST FAILED
    exit /b 1
) else (
    echo TEST PASSED
)
