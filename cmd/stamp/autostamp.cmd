@echo off
copy /B /Y %1\bee2cmd.exe %1\_bee2cmd.exe > nul
%1\_bee2cmd.exe stamp -s %1\bee2cmd.exe
del /Q /F %1\_bee2cmd.exe > nul
