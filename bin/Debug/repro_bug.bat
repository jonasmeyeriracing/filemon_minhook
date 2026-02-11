@echo off
cd /d "%~dp0"
if exist temp_out rmdir /s /q temp_out
if exist foooo.txt del foooo.txt
mkdir temp_out
"%~dp0filemon_commandline_run.exe" foooo.txt "%~dp0file_workload.exe" .\temp_out
echo.
echo --- foooo.txt ---
for %%A in (foooo.txt) do echo Size: %%~zA bytes
