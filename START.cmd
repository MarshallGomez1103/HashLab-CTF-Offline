@echo off
cd /d "%~dp0"
if not exist "%~dp0tools\python\pythonw.exe" (
  echo El paquete esta incompleto: falta Python portable.
  pause
  exit /b 1
)
"%~dp0tools\python\pythonw.exe" "%~dp0launcher_gui.py"
