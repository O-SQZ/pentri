@echo off
cd /d "%~dp0"
if exist "runtime\node.exe" (
  "runtime\node.exe" scripts\desktop.mjs
) else (
  node scripts\desktop.mjs
)
if errorlevel 1 pause
