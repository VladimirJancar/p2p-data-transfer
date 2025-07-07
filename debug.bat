@echo off

REM
start cmd /k py .\comm.py --selfport 8889 --peerport 8888

REM
timeout /t 2 >nul
start cmd /k py .\comm.py --selfport 8888 --peerport 8889
