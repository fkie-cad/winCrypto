@echo off
setlocal

set prog_name=%~n0
set user_dir="%~dp0"
set "my_dir=%my_dir:~1,-2%"

set bin_path=
set label=

set /a MODE_NONE=0
set /a MODE_ADD=1
set /a MODE_DEL=2

set /a verbose=0
set /a mode=%MODE_ADD%
set ico=

if [%1]==[] goto help
if ["%1"]==[""] goto help

GOTO :ParseParams

:ParseParams

    if [%1]==[/?] goto help
    if [%1]==[/h] goto help
    if [%1]==[/help] goto help

    IF "%~1"=="/p" (
        SET bin_path=%~2
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/l" (
        SET label=%~2
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/d" (
        SET /a mode=%MODE_DEL%
        goto reParseParams
    )
    IF "%~1"=="/ico" (
        SET "ico=%~2"
        SHIFT
        goto reParseParams
    )
    IF "%~1"=="/v" (
        SET /a verbose=1
        goto reParseParams
    )
    
    :reParseParams
        SHIFT
        if [%1]==[] goto main

GOTO :ParseParams


:main

    if ["%bin_path%"] == [""] call :usage & goto exitMain
    if ["%bin_path%"] == [""] call :usage & goto exitMain
    if ["%label%"] == [""] call :usage & goto exitMain
    if ["%label%"] == [""] call :usage & goto exitMain

    IF not exist "%bin_path%" (
        echo Binary not found at "%bin_path%"!
        echo Place it there or give a correct /b ^<path^>
        exit /b 0
    )

    if %verbose% == 1 (
        echo bin_path=%bin_path%
        echo label=%label%
    )
    
    if %mode% EQU %MODE_ADD% (
        call :addEntry
    ) else if %mode% EQU %MODE_DEL% (
        call :deleteEntry
    ) else (
        echo [e] Unknown mode!
        exit /b 1
    )
    
    :exitMain
    endlocal
    exit /B %ERRORLEVEL%


:addEntry
setlocal
    REM set "group_key=HKEY_CURRENT_USER\SOFTWARE\Classes\*\shell\%label%.Group"
    set "group_key=HKEY_CLASSES_ROOT\*\shell\%label%.Group"
    set "cmd_key=hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell"
    
    reg add "%group_key%" /v MUIVerb /t REG_SZ /d "%label%" /f
    reg add "%group_key%" /v SubCommands /t REG_SZ /d "md5.cmd;sha1.cmd;sha256.cmd;sha384.cmd;sha512.cmd;" /f
    if ["%ico%"] NEQ [""] (
        reg add ""%group_key%"" /v Icon /t REG_SZ /d "%ico%"
    )

    reg add "%cmd_key%\md5.cmd" /t REG_SZ /d "md5" /f
    reg add "%cmd_key%\md5.cmd\Command" /t REG_SZ /d "cmd /k %bin_path%\md5.exe \"%1\"" /f

    reg add "%cmd_key%\sha1.cmd" /t REG_SZ /d "sha1" /f
    reg add "%cmd_key%\sha1.cmd\Command" /t REG_SZ /d "cmd /k %bin_path%\sha1.exe \"%1\"" /f

    reg add "%cmd_key%\sha256.cmd" /t REG_SZ /d "sha256" /f
    reg add "%cmd_key%\sha256.cmd\Command" /t REG_SZ /d "cmd /k %bin_path%\sha256.exe \"%1\"" /f

    reg add "%cmd_key%\sha384.cmd" /t REG_SZ /d "sha384" /f
    reg add "%cmd_key%\sha384.cmd\Command" /t REG_SZ /d "cmd /k %bin_path%\sha384.exe \"%1\"" /f

    reg add "%cmd_key%\sha512.cmd" /t REG_SZ /d "sha512" /f
    reg add "%cmd_key%\sha512.cmd\Command" /t REG_SZ /d "cmd /k %bin_path%\sha512.exe \"%1\"" /f

    endlocal
    exit /B %ERRORLEVEL%


:deleteEntry
setlocal
    REM set "group_key=HKEY_CURRENT_USER\SOFTWARE\Classes\*\shell\%label%.Group"
    set "group_key=HKEY_CLASSES_ROOT\*\shell\%label%.Group"
    set "cmd_key=hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell"
    
    reg DELETE "%group_key%" /f
    
    reg DELETE "%cmd_key%\md5.cmd" /f
    reg DELETE "%cmd_key%\sha1.cmd" /f
    reg DELETE "%cmd_key%\sha256.cmd" /f
    reg DELETE "%cmd_key%\sha384.cmd" /f
    reg DELETE "%cmd_key%\sha512.cmd" /f

    endlocal
    exit /B %ERRORLEVEL%

:usage
    echo Usage: %prog_name% /p ^<path^> /l ^<label^> [/pb ^<params^>] [/pa ^<params^>] [/ico ^<path^>] [/d] [/v] [/h]
    exit /B 0

:help
    call :usage
    echo.
    echo /p Path to the binaries parent dir. Must not have spaces at the moment!
    echo /l Label to show up in the context menu.
    echo /d Delete entry specified by /l label.
    echo /ico Icon to show up next to the entry group.
    echo /v Verbose mode.
    echo /h Print this.
    
    exit /B 0
