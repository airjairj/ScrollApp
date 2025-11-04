@echo off
set SRC=..\pc_server.c
set OUT=..\exe\pc_server.exe

echo Building %OUT%...
gcc -Wall -O2 -o %OUT% %SRC% -lws2_32
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)
echo Build succeeded.