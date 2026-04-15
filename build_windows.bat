@echo off
setlocal

set CXX=g++
set CXXFLAGS=-std=c++17 -Wall -Wextra -pedantic -O2
set COMMON_SRC=scanner.cpp hasher.cpp signatures.cpp heuristic.cpp report.cpp quarantine.cpp scan_engine.cpp interactive_cli.cpp

echo Building console executable...
%CXX% %CXXFLAGS% -o MiniAntivirus.exe main.cpp %COMMON_SRC% -lssl -lcrypto
if errorlevel 1 exit /b 1

echo Building GUI executable...
%CXX% %CXXFLAGS% -mwindows -o MiniAntivirusGUI.exe gui_main.cpp %COMMON_SRC% -lssl -lcrypto -lshell32 -lole32
if errorlevel 1 exit /b 1

echo Build complete:
echo   MiniAntivirus.exe
echo   MiniAntivirusGUI.exe
