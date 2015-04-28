@echo off
copy /B /Y %1\stamp.exe %1\_stamp.exe > nul
%1\_stamp.exe -s %1\stamp.exe
del /Q /F %1\_stamp.exe > nul
