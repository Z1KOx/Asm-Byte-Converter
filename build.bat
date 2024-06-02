@echo off
color C

:: Create build directory if it doesn't exist and navigate to it
if not exist build mkdir build
cd build

:: Generate Visual Studio solution using CMake
cmake -G "Visual Studio 17 2022" -A Win32 ..
if %ERRORLEVEL% neq 0 (
    echo Error executing CMake!
    ping 127.0.0.1 -n 3 > nul
    exit /b %ERRORLEVEL%
)

:: Build the project using the generated Visual Studio solution in Release mode
cmake --build . --config Release
if %ERRORLEVEL% neq 0 (
    echo Error building the project!
    ping 127.0.0.1 -n 3 > nul
    exit /b %ERRORLEVEL%
)

cls
color 2

:: Get the current directory
for %%I in (.) do set "CURRENT_DIR=%%~fI"

:: Define the source and destination paths for the DLL
set "DLL_SOURCE=C:\Users\admin\source\repos\OpcodeToBytes\dependencies\keystone\bin\keystone.dll"
set "DLL_DEST=%CURRENT_DIR%\Release"

:: Check if DLL_SOURCE exists, and if not, exit with error
if not exist "%DLL_SOURCE%" (
    echo keystone.dll not found at "%DLL_SOURCE%"
    ping 127.0.0.1 -n 3 > nul
    exit /b 1
)

:: Create destination directory if it doesn't exist
if not exist "%DLL_DEST%" mkdir "%DLL_DEST%"

:: Copy the keystone.dll to the Release directory
copy /Y "%DLL_SOURCE%" "%DLL_DEST%" > nul

:: Check if copying was successful, and if not, exit with the error level
if %ERRORLEVEL% neq 0 (
    echo Error copying keystone.dll!
    ping 127.0.0.1 -n 3 > nul
    exit /b %ERRORLEVEL%
)

:: Define the destination path for the executable
set "EXECUTABLE_DEST=%CURRENT_DIR%\Release"

echo The executable is located at: %EXECUTABLE_DEST%

pause
exit