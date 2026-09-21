@echo off
cd /d "%~dp0"
title ActShield System Runner
echo ========================================================
echo Starting ActShield: Live Backend + Frontend Dashboard
echo ========================================================
python run_live.py
pause

