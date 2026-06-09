@echo off
setlocal
cd /d "%~dp0"
set "LAUNCHER=%~dp0project\protect_launcher.py"
if not exist "%LAUNCHER%" set "LAUNCHER=%~dp0protect_launcher.py"
python "%LAUNCHER%" menu
pause
