@echo off
:: Start OrphanGuard in the system tray (no console window)
start "" "%~dp0venv\Scripts\pythonw.exe" "%~dp0orphan_guard.py"
