#ifndef ARGS_H
#define ARGS_H

//#include <windows.h>



#define LIN_PARAM_IDENTIFIER '-'
#define WIN_PARAM_IDENTIFIER '/'
#define LIN_PARAM_IDENTIFIER_W L'-'
#define WIN_PARAM_IDENTIFIER_W L'/'
#define PARAM_IDENTIFIER WIN_PARAM_IDENTIFIER

#define GET_ARG_VALUE(__argc__, __argv__, __i__, __id__) ( __i__ < __argc__ - __id__ ) ? __argv__[__i__+__id__] : NULL
#define IS_PARAM(__arg__) (__arg__ != NULL && ( __arg__[0] == LIN_PARAM_IDENTIFIER || __arg__[0] == WIN_PARAM_IDENTIFIER) )
#define IS_PARAM_W(__arg__) (__arg__ != NULL && ( __arg__[0] == LIN_PARAM_IDENTIFIER_W || __arg__[0] == WIN_PARAM_IDENTIFIER_W) )
#define IS_VALUE(__val__) (__val__ != NULL)
#define IS_1C_ARG(_a_, _v_) ( ( _a_[0] == LIN_PARAM_IDENTIFIER || _a_[0] == WIN_PARAM_IDENTIFIER ) && _a_[1] == _v_ && _a_[2] == 0 )
#define IS_1C_ARG_W(_a_, _v_) ( ( _a_[0] == LIN_PARAM_IDENTIFIER_W || _a_[0] == WIN_PARAM_IDENTIFIER_W ) && _a_[1] == _v_ && _a_[2] == 0 )
#define IS_2C_ARG(_a_, _v_) \
    ( ( _a_[0] == LIN_PARAM_IDENTIFIER || _a_[0] == WIN_PARAM_IDENTIFIER ) \
    && _a_[1] == ((_v_&0x0000FF00)>>0x08)  \
    && _a_[2] == ((_v_&0x000000FF))  \
    && _a_[3] == 0 )
#define IS_3C_ARG(_a_, _v_) \
    ( ( _a_[0] == LIN_PARAM_IDENTIFIER || _a_[0] == WIN_PARAM_IDENTIFIER ) \
    && _a_[1] == ((_v_&0x00FF0000)>>0x10)  \
    && _a_[2] == ((_v_&0x0000FF00)>>0x08)  \
    && _a_[3] == ((_v_&0x000000FF))  \
    && _a_[4] == 0 )
#define IS_4C_ARG(_a_, _v_) \
    ( ( _a_[0] == LIN_PARAM_IDENTIFIER || _a_[0] == WIN_PARAM_IDENTIFIER ) \
    && _a_[1] == ((_v_&0xFF000000)>>0x18)  \
    && _a_[2] == ((_v_&0x00FF0000)>>0x10)  \
    && _a_[3] == ((_v_&0x0000FF00)>>0x08)  \
    && _a_[4] == ((_v_&0x000000FF))  \
    && _a_[5] == 0 )
#define BREAK_ON_NOT_A_VALUE(__val__, __s__, __info__) \
{ \
    if ( ! IS_VALUE(__val__) ) \
    { \
        __s__ = ERROR_INVALID_PARAMETER; \
        EPrint("%s", __info__); \
        break; \
    } \
}

BOOL isAskForHelp(INT argc, CHAR** argv);
BOOL isAskForHelpW(INT argc, WCHAR** argv);
BOOL isArgOfType(const CHAR* arg, const CHAR* type);
BOOL isArgOfTypeW(const WCHAR* arg, const WCHAR* type);
BOOL hasValue(const char* type, int i, int end_i);




BOOL isAskForHelp(INT argc, CHAR** argv)
{
    int i = 1;
    if ( argc < i+1 )
        return FALSE;

    return IS_1C_ARG(argv[i], 'h') || IS_1C_ARG(argv[i], '?') || isArgOfType(argv[1], "help");
}

BOOL isAskForHelpW(INT argc, WCHAR** argv)
{
    int i = 1;
    if ( argc < i+1 )
        return FALSE;

    return IS_1C_ARG_W(argv[i], L'h') || IS_1C_ARG_W(argv[i], L'?') || isArgOfTypeW(argv[1], L"help");
}

BOOL isArgOfType(const CHAR* arg, const CHAR* type)
{
    size_t type_ln;

    type_ln = strlen(type);
    
    return ( arg[0] == LIN_PARAM_IDENTIFIER || arg[0] == WIN_PARAM_IDENTIFIER ) && 
        strnlen(&arg[1], 10) == type_ln && 
        strncmp(&arg[1], type, type_ln) == 0;
}

BOOL isArgOfTypeW(const WCHAR* arg, const WCHAR* type)
{
    size_t type_ln;

    type_ln = wcslen(type);
    
    return ( arg[0] == LIN_PARAM_IDENTIFIER_W || arg[0] == WIN_PARAM_IDENTIFIER_W ) && 
        wcslen(&arg[1]) == type_ln && 
        wcscmp(&arg[1], type) == 0;
}

BOOL hasValue(const char* type, int i, int last_i)
{
    if ( i >= last_i )
    {
        printf("INFO: Arg \"%c%s\" has no value! Skipped!\n", PARAM_IDENTIFIER, type);
        return FALSE;
    }

    return TRUE;
}

#endif
