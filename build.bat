@echo off
setlocal enabledelayedexpansion

set my_name=%~n0
set my_dir="%~dp0"
set "my_dir=%my_dir:~1,-2%"


set /a DP_FLAG=1
set /a EP_FLAG=2


:: project ids
set /a id=0
set /a AES=%id%
set /a id+=1
set /a B64=%id%
set /a id+=1
set /a MD5=%id%
set /a id+=1
set /a SH1=%id%
set /a id+=1
set /a SH2=%id%
set /a id+=1
set /a SH3=%id%
set /a id+=1
set /a SH5=%id%
set /a id+=1
set /a "PROJ_ID_MAX=%id%-1"
set /a PROJ_COUNT=%id%

:: project file names
set projects[%AES%]=aes
set projects[%B64%]=base64
set projects[%MD5%]=hash
set projects[%SH1%]=hash
set projects[%SH2%]=hash
set projects[%SH3%]=hash
set projects[%SH5%]=hash

:: sub type names
set sub_type[%AES%]=aes
set sub_type[%B64%]=base64
set sub_type[%MD5%]=md5
set sub_type[%SH1%]=sha1
set sub_type[%SH2%]=sha256
set sub_type[%SH3%]=sha384
set sub_type[%SH5%]=sha512

:: do compile flags
set /a cmpl[%AES%]=0
set /a cmpl[%B64%]=0
set /a cmpl[%MD5%]=0
set /a cmpl[%SH1%]=0
set /a cmpl[%SH2%]=0
set /a cmpl[%SH3%]=0
set /a cmpl[%SH5%]=0

:: batch params
set cmdparams[%AES%]=/aes
set cmdparams[%B64%]=/b64
set cmdparams[%MD5%]=/md5
set cmdparams[%SH1%]=/sh1
set cmdparams[%SH2%]=/sh2
set cmdparams[%SH3%]=/sh3
set cmdparams[%SH5%]=/sh5


set proj_dir=.
set proj_ftype=.vcxproj

set /a all=0
set /a cln=0
set /a hash=0

set /a debug=0
set /a release=0

set /a bitness=64
set /a pdb=0
set /a debug_print=%EP_FLAG%
set platform=
set pts=v143
set /a rtl=0
set /a verbose=0



GOTO :ParseParams

:ParseParams
    if [%1]==[/?] goto help
    if [%1]==[/h] goto help
    if [%1]==[/help] goto help
    
    :: projects
    FOR /L %%i IN (0 1 %PROJ_ID_MAX%) DO  (
        if /i [%~1] == [!cmdparams[%%i]!] (
            set /a cmpl[%%i]=1
            goto reParseParams
        )
    )
    
    IF /i "%~1"=="/all" (
        SET /a all=1
        goto reParseParams
    )

    IF /i "%~1"=="/hash" (
        SET /a hash=1
        goto reParseParams
    )

    IF /i "%~1"=="/cln" (
        SET /a cln=1
        goto reParseParams
    )

    IF /i "%~1"=="/d" (
        SET /a debug=1
        goto reParseParams
    )
    IF /i "%~1"=="/r" (
        SET /a release=1
        goto reParseParams
    )
    
    IF /i "%~1"=="/dp" (
        SET /a "debug_print=%~2"
        SHIFT
        goto reParseParams
    )
    IF /i "%~1"=="/dpf" (
        SET /a "debug_print=%debug_print%|DP_FLAG"
        goto reParseParams
    )
    IF /i "%~1"=="/epf" (
        SET /a "debug_print=%debug_print%|EP_FLAG"
        goto reParseParams
    )

    IF /i "%~1"=="/pdb" (
        SET /a pdb=1
        goto reParseParams
    )
    IF /i "%~1"=="/rtl" (
        SET /a rtl=1
        goto reParseParams
    )

    IF /i "%~1"=="/pts" (
        SET pts=%~2
        SHIFT
        goto reParseParams
    )

    IF /i "%~1"=="/b" (
        SET /a bitness=%~2
        SHIFT
        goto reParseParams
    )

    IF /i "%~1"=="/v" (
        SET /a verbose=1
        goto reParseParams
    ) ELSE (
    IF /i "%~1" neq "" (
        echo Unknown option : "%~1"
    ))
    
    :reParseParams
    SHIFT
    if [%1]==[] goto main

GOTO :ParseParams


:main

    set /a "s=%debug%+%release%"
    if %s% == 0 (
        set /a debug=0
        set /a release=1
    )

    set platform=
    if %bitness% == 64 (
        set platform=x64
    )
    if %bitness% == 32 (
        set platform=x86
    )
    if platform == [] (
        echo [e] Bitness /b has to be 32 or 64!
        EXIT /B 1
    )

    if %all% == 1 (
        FOR /L %%i IN (0 1 %PROJ_ID_MAX%) DO  (
            set /a cmpl[%%i]=1
        )
    ) else if %hash% == 1 (
        set /a cmpl[%MD5%]=1
        set /a cmpl[%SH1%]=1
        set /a cmpl[%SH2%]=1
        set /a cmpl[%SH3%]=1
        set /a cmpl[%SH5%]=1
    )

    
    :: check if a project is set
    set /a s=0
    FOR /L %%i IN (0 1 %PROJ_ID_MAX%) DO  (
        if !cmpl[%%i]! == 1 (
            set /a s=1
            goto endLoop
        )
    )
    :endLoop
    set /a "s=%s%+%cln%"
    if !s! == 0 (
        REM FOR /L %%i IN (0 1 %PROJ_ID_MAX%) DO  (
        REM    set /a cmpl[%%i]=1
        REM )
        echo [e] No project set to build!
        goto usage
    )

    if %verbose% == 1 (
        FOR /L %%i IN (0 1 %PROJ_ID_MAX%) DO  (
            echo !projects[%%i]!: !cmpl[%%i]!
        )
        echo.
        echo debug: %debug%
        echo release: %release%
        echo bitness: %bitness%
        echo pdb: %pdb%
        echo dprint: %debug_print%
        echo rtl: %rtl%
        echo pts: %pts%
    )
    
    if %cln% == 1 (
        echo removing "%my_dir%\build"
        rmdir /s /q "%my_dir%\build" >nul 2>&1 
    )
    
    :: build projects
    FOR /L %%i IN (0 1 %PROJ_ID_MAX%) DO (
        if !cmpl[%%i]! == 1 (
            call :build !projects[%%i]! %%i

            if NOT !ERRORLEVEL! == 0 (
                goto buildLoopEnd
            )
        )
    )
    :buildLoopEnd
    
    echo build finished with code : %ERRORLEVEL%
    endlocal
    exit /B !ERRORLEVEL!



:build
    SETLOCAL
        set proj_name=%~1
        set proj_id=%~2
        set proj=%proj_dir%\%proj_name%%proj_ftype%
        set sub_type=!sub_type[%proj_id%]!

        if %debug%==1 call :buildEx %proj%,%platform%,Debug,%debug_print%,%rtl%,%pdb%,%pts%,%sub_type%
        if %release%==1 call :buildEx %proj%,%platform%,Release,%debug_print%,%rtl%,%pdb%,%pts%,%sub_type%
    ENDLOCAL
    
    EXIT /B %ERRORLEVEL%
    
:buildEx
    SETLOCAL
        set proj=%~1
        set platform=%~2
        set conf=%~3
        set /a dpf=%~4
        set /a rtl=%~5
        set /a pdb=%~6
        set pts=%~7
        set sub_type=%~8
        
        :: print flags
        set /a "dp=%dpf%&~EP_FLAG"
        set /a "ep=%dpf%&EP_FLAG"
        if not %ep% == 0 ( set /a ep=1 )

        if %rtl% == 1 (
            set rtl=%conf%
        ) else (
            set rtl=None
        )

        :: pdbs
        if [%conf%] EQU [Debug] (
            set /a pdb=1
        )

        if %verbose% EQU 1 (
            echo build
            echo  - Project=%proj%
            echo  - Platform=%platform%
            echo  - Configuration=%conf%
            echo  - DebugPrint=%dp%
            echo  - RuntimeLib=%rtl%
            echo  - DebugPrint=%dp%
            echo  - ErrorPrint=%ep%
            echo  - pdb=%pdb%
            echo  - pts=%pts%
            echo  - sub_type=%sub_type%
            echo.
        )
        
        msbuild %proj% /p:Platform=%platform% /p:Configuration=%conf% /p:DebugPrint=%dp% /p:ErrorPrint=%ep% /p:RuntimeLib=%rtl% /p:PDB=%pdb% /p:PlatformToolset=%pts% /p:SubType=%sub_type%
        echo.
        echo ----------------------------------------------------
        echo.
        echo.
    ENDLOCAL
    
    EXIT /B %ERRORLEVEL%




:usage
    echo|set /p="Usage: %my_name% [/all] "
    FOR /L %%i IN (0 1 %PROJ_ID_MAX%) DO  (
        echo|set /p="[!cmdparams[%%i]!] "
    )
    echo|set /p="[/cln] [/d] [/r] [/dp <value>] [/dpf] [/epf] [/pdb] [/rtl] [/v] [/h]"
    exit /B 0
    

:help
    call :usage
    echo.
    echo Targets:
    echo /aes: Build Aes tool.
    echo /b64: Build base64 tool.
    echo /md5: Build Md5 tool.
    echo /sh1: Build Sha1 tool.
    echo /sh2: Build Sha256 tool.
    echo /sh3: Build Sha384 tool.
    echo /sh5: Build Sha512 tool.
    echo /all: Build all tools.
    echo /hash: Build all hash tools: md5, sha1, sha256, sha384, sha512.
    echo /cln: Clean build folder.
    echo.
    echo Options:
    echo /d: Build in debug mode.
    echo /r: Build in release mode.
    echo /b: Bitness of exe. 32^|64. Default: 64.
    echo /pdb: Compile with pdbs.
    echo /rtl: Compile with statically included RuntimeLibrary.
    echo /pts: Set the PlatformToolset. Defaults to "v142".
    echo.
    echo Debug print:
    echo /dp: Debug print flag value.
    echo /dpf: Set debug print flag (%DP_FLAG%). Print debug stuff.
    echo /epf: Set error print flag (%EP_FLAG%). Print errors.
    echo.
    echo /v: More verbose output.
    echo /h: Print this.
    echo.
    exit /B 0
