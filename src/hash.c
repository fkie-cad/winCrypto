#include "hash.h"

#include <stdio.h>
#include <stdlib.h>

#include "inc/warnings.h"
#include "inc/nt.h"
#include "shared/print.h"
#include "shared/Args.h"
#include "files/FilesW.h"


#define TYPE_MD5_STR L"Md5"
#define TYPE_SHA1_STR L"Sha1"
#define TYPE_SHA2_STR L"Sha256"

#if HASH_TYPE == 5
    #define HASH_TYPE_STR TYPE_MD5_STR
    #define BIN_NAME TYPE_MD5_STR
    #define HASH_BYTES_LN MD5_BYTES_LN
    #define HASH_STRING_LN MD5_STRING_LN
#elif HASH_TYPE == 128
    #define HASH_TYPE_STR TYPE_SHA1_STR
    #define BIN_NAME TYPE_SHA1_STR
    #define HASH_BYTES_LN SHA1_BYTES_LN
    #define HASH_STRING_LN SHA1_STRING_LN
#elif HASH_TYPE == 256
    #define HASH_TYPE_STR TYPE_SHA2_STR
    #define BIN_NAME TYPE_SHA2_STR
    #define HASH_BYTES_LN SHA256_BYTES_LN
    #define HASH_STRING_LN SHA256_STRING_LN
#else
    #error No valid HASH_TYPE set: (5, 128, 256)
#endif


HashCtxt ctxt;

#define BIN_VS "1.0.5"
#define BIN_LC "11.12.2023"


int compare(int argc, WCHAR** argv);
void printColored(CHAR* value, UINT16 attributes);

void fileCB(wchar_t* file);
int runList(int argc, WCHAR** argv);

void printVersion()
{
    printf("%ws\n", BIN_NAME);
    printf("Version: %s\n", BIN_VS);
    printf("Last changed: %s\n", BIN_LC);
    printf("Compiled: %s %s\n", __DATE__, __TIME__);
}

void printUsage()
{
    printf("Usage: %ws [/h] [/c] path ...\n", BIN_NAME);
}

void printHelp()
{
    printVersion();
    wprintf(L"\n");
    printUsage();
    wprintf(L"\n");
    wprintf(L"Options:\n");
    wprintf(L" /c: Compare path1 with path2 or with a hash value.\n");
    wprintf(L" /h: Print this\n");
    wprintf(L" path: One or more pathes to files or dirs for hash calculation.\n");
}

int __cdecl wmain(int argc, WCHAR** argv)
{
    int s = 0;
    BOOL compare_f = FALSE;

    if ( argc < 2 )
    {
        printUsage();
        return 1;
    }
    if ( IS_PARAM_W(argv[1]) )
    {
        if ( isAskForHelpW(argc, argv) )
        {
            printHelp();
            return;
        }
        if ( IS_1C_ARG_W(argv[1], L'c') )
        {
            compare_f = TRUE;
        }
    }
    
#if HASH_TYPE == 5
    initHashCtxt(&ctxt, BCRYPT_MD5_ALGORITHM);
#elif HASH_TYPE == 128
    initHashCtxt(&ctxt, BCRYPT_SHA1_ALGORITHM);
#elif HASH_TYPE == 256
    initHashCtxt(&ctxt, BCRYPT_SHA256_ALGORITHM);
#endif

    if ( compare_f )
    {
        s = compare(argc, argv);
    }
    else
    {
        s = runList(argc, argv);
    }
    

    cleanHashCtxt(&ctxt);

    return s;
}

int compare(int argc, WCHAR** argv)
{
    INT s = 0;
    WCHAR full_path1[MAX_PATH];
    WCHAR* base_name1 = NULL;
    UINT8 hash1_bytes[HASH_BYTES_LN];

    WCHAR full_path2[MAX_PATH];
    WCHAR* base_name2 = NULL;
    UINT8 hash2_bytes[HASH_BYTES_LN];
    WCHAR* ptr = NULL;
    
    SIZE_T i;
    SIZE_T j;

    if ( argc < 4 )
    {
        EPrint("You have to provide two pathes or a path and a value to compare!");
        return -1;
    }
    
    DPrintW(L"file1: %ws\n", argv[2]);
    memset(full_path1, 0, MAX_PATH*2);
    s = ntGetFullPathName(argv[2], MAX_PATH, full_path1, &base_name1);
    if ( s == 0 )
    {
        s = GetLastError();
        EPrint("GetFullPathNameW failed! (0x%x)\n", s);
        goto clean;
    }
    s = 0;
    DPrintW(L" - full_path1: %ws\n", full_path1);
    DPrintW(L" - base_name1: %ws\n", base_name1);

    if ( !ntFileExists(full_path1) )
    {
        wprintf(L"ERROR: Path \"%s\" does not exist!", full_path1);
        return -2;
    }

    hashFileC(full_path1, hash1_bytes, (UINT16)ctxt.HashSize, &ctxt);
    lPrintHash(hash1_bytes, ctxt.HashSize, full_path1, HASH_TYPE_STR);

    ptr = argv[3];
    DPrintW(L"file2: %ws\n", ptr);
    memset(full_path2, 0, MAX_PATH*2);
    s = ntGetFullPathName(ptr, MAX_PATH, full_path2, &base_name2);
    if ( s == 0 )
    {
        s = GetLastError();
        EPrint("GetFullPathNameW failed! (0x%x)\n", s);
        goto clean;
    }
    
    if ( ntFileExists(full_path2) )
    {
        hashFileC(full_path2, hash2_bytes, (UINT16)ctxt.HashSize, &ctxt);
        lPrintHash(hash2_bytes, ctxt.HashSize, full_path2, HASH_TYPE_STR);
        if ( memcmp(hash1_bytes, hash2_bytes, ctxt.HashSize) == 0 )
        {
            printColored("equal!", FOREGROUND_GREEN);
        }
        else
        {
            printColored("not equal!", FOREGROUND_RED);
        }
    }
    else
    {
        CHAR byte[3];
        SIZE_T n = wcslen(ptr);
        if ( n != HASH_STRING_LN )
        {
            wprintf(L"ERROR: \"%s\" is neither an existing file nor a valid %s value!", ptr, HASH_TYPE_STR);
            return -3;
        }

        byte[2] = 0;
        for ( i = 0, j = 0; i < ctxt.HashSize; i++, j+=2 )
        {
            byte[0] = (CHAR)ptr[j];
            byte[1] = (CHAR)ptr[j + 1];
            __try {
                hash2_bytes[i] = (UINT8)strtoull(byte, NULL, 16);
            }
            __except ( EXCEPTION_EXECUTE_HANDLER )
            {
                return -1;
            }
        }

        wprintf(L"and\n");
        wprintf(L"%s\n", ptr);
        if ( memcmp(hash1_bytes, hash2_bytes, ctxt.HashSize) == 0 )
        {
            printColored("equal!", FOREGROUND_GREEN);
        }
        else
        {
            printColored("not equal!", FOREGROUND_RED);
        }
    }

clean:
    return s;
}

void printColored(CHAR* value, UINT16 attributes)
{
    HANDLE hStdout;
    UINT16 wOldColorAttrs;
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
    GetConsoleScreenBufferInfo(hStdout, &csbiInfo);
    wOldColorAttrs = csbiInfo.wAttributes;
    SetConsoleTextAttribute(hStdout, attributes);
    printf("%s\n", value);
    SetConsoleTextAttribute(hStdout, wOldColorAttrs);
}

int runList(int argc, WCHAR** argv)
{
    int s = 0;
    WCHAR full_path[MAX_PATH];
    WCHAR* base_name = NULL;
    int files_i = 1;
    int i;

    for ( i = files_i; i < argc; i++ )
    {
        DPrintW(L"file[%d]: %ws\n", i, argv[i]);
        memset(full_path, 0, MAX_PATH*2);
        s = ntGetFullPathName(argv[i], MAX_PATH, full_path, &base_name);
        if ( s == 0 )
        {
            s = GetLastError();
            EPrint("GetFullPathNameW failed! (0x%x)\n", s);
            goto clean;
        }
        DPrintW(L" - full_path: %ws\n", full_path);
        DPrintW(L" - base_name: %ws\n", base_name);

        if ( ntFileExists(full_path) )
        {
            fileCB(full_path);
        }
        else if ( ntDirExists(full_path) )
        {
            s = hashDir(full_path);
        }
        else
        {
            EPrintW(L"Path \"%s\" does not exist!", full_path);
        }
    }

clean:
    return s;
}

void fileCB(wchar_t* file)
{
    UINT8 hash_bytes[HASH_BYTES_LN];
    RtlZeroMemory(hash_bytes, HASH_BYTES_LN);
    DPrintW(L"fileCB: %ws\n", file);
    INT s = hashFileC(file, hash_bytes, (UINT16)ctxt.HashSize, &ctxt);
    if ( s != 0 )
        return;
    lPrintHash(hash_bytes, ctxt.HashSize, file, HASH_TYPE_STR);
}

int hashDir(_In_ WCHAR* Path)
{
    DPrintW(L"hashDir(%s)\n", Path);
    int s = 0;
    FileCallback cb;
    cb = &fileCB;
    //CHAR* types[2] = { ".exe", ".dll" };

    actOnFilesInDir(Path, cb, NULL, TRUE);

    return s;
}

void lPrintHash(_In_ PUINT8 Bytes, _In_ ULONG Size, _In_ WCHAR* File, _In_ PWCHAR Type)
{
    ULONG i;
    
    if ( wcslen(File) < 4 )
        return;

    wprintf(L"%ws of %s:\n", Type, &File[4]);
    for (i = 0; i < Size; i++)
    {
        wprintf(L"%02x", Bytes[i]);
    }
    wprintf(L"\n");
}
