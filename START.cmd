@echo off
cd /d "%~dp0"
if not exist "%~dp0tools\python\pythonw.exe" (
  echo Este ZIP no contiene Python portable. Descarga el paquete completo:
  echo https://github.com/MarshallGomez1103/HashLab-CTF-Offline/releases/download/v1.0.0/HashLab-CTF-offline-2026-11-17-final.zip
  pause
  exit /b 1
)
if not exist "%~dp0private_data\wordlists\rockyou.txt" (
  if not exist "%~dp0private_data\wordlists\rockyou.part.00" goto missing_wordlist
  if not exist "%~dp0private_data\wordlists\rockyou.part.01" goto missing_wordlist
  echo Preparando el diccionario RockYou. Espera un momento...
  copy /y /b "%~dp0private_data\wordlists\rockyou.part.00"+"%~dp0private_data\wordlists\rockyou.part.01" "%~dp0private_data\wordlists\rockyou.tmp" >nul
  if errorlevel 1 goto copy_failed
  for %%F in ("%~dp0private_data\wordlists\rockyou.tmp") do if not "%%~zF"=="139921497" goto copy_failed
  move /y "%~dp0private_data\wordlists\rockyou.tmp" "%~dp0private_data\wordlists\rockyou.txt" >nul
  if errorlevel 1 goto copy_failed
)
if not exist "%~dp0private_data\wordlists\crackstation.txt.gz" (
  echo Preparando CrackStation. Esto puede tardar unos minutos...
  "%~dp0tools\python\python.exe" "%~dp0prepare_wordlist.py"
  if errorlevel 1 (
    echo No se pudo preparar CrackStation. Extrae el ZIP completo a una carpeta con espacio libre.
    pause
    exit /b 1
  )
)
"%~dp0tools\python\pythonw.exe" "%~dp0launcher_gui.py"
exit /b %errorlevel%

:missing_wordlist
echo Faltan partes del diccionario. Extrae el ZIP completo antes de abrir START.cmd.
pause
exit /b 1

:copy_failed
echo No se pudo preparar RockYou. Extrae el ZIP a una carpeta con espacio libre y permisos de escritura.
pause
exit /b 1
