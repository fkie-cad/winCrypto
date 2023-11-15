#include "base64.h"

#include <strsafe.h>

#include <stdio.h>
#include <stdlib.h>

#include "inc/nt.h"
#include "shared/print.h"
#include "shared/Converter.h"
#include "shared/Args.h"
#include "files/FilesW.h"

#include "shared/argParsing.h"

#include "crypto/Base64wc.h"


#define BN "Base64"
#define VS "1.0.2"
#define LC "25.05.2023"

#define FLAG_VERBOSE              (0x1)
#define FLAG_DECODE               (0x2)
#define FLAG_ENCODE               (0x4)
#define FLAG_BYTES_ALLOC          (0x8)
#define FLAG_PRINT_RESULT_A      (0x10)
#define FLAG_PRINT_RESULT_B      (0x20)
#define FLAG_PRINT_RESULT_8      (0x40)
#define FLAG_PRINT_RESULT_16     (0x80)
#define FLAG_PRINT_RESULT_32    (0x100)
#define FLAG_PRINT_RESULT_64    (0x200)
#define FLAG_LF                 (0x400)
#define FLAG_CRLF               (0x800)

#define FLAG_PRINT_RESULT (FLAG_PRINT_RESULT_A|FLAG_PRINT_RESULT_B|FLAG_PRINT_RESULT_8|FLAG_PRINT_RESULT_16|FLAG_PRINT_RESULT_32|FLAG_PRINT_RESULT_64)


typedef struct _CMD_PARAMS {
    PUINT8 Bytes;
    ULONG BytesSize;
    PWCHAR InPath;
    PWCHAR OutPath;
    UINT32 LineBreak;
    UINT32 Flags;
} CMD_PARAMS, * PCMD_PARAMS;


BOOL parseArgs(_In_ INT argc, _In_reads_(argc) CHAR** argv, _Out_ PCMD_PARAMS Params);
BOOL checkArgs(_In_ PCMD_PARAMS Params);
void printUsage();
void printHelp();

INT writeResult(_In_ PWCHAR Path, _In_ PVOID Buffer, _In_ ULONG BufferSize);
VOID printResult(_In_ PCHAR Label, _In_ ULONG Flags, _In_ PVOID Buffer, _In_ ULONG BufferSize);


int __cdecl main(int argc, CHAR** argv)
{
    int s = 0;
    
    CMD_PARAMS params = { 0 };

    PUINT8 buffer = NULL;
    ULONG bufferSize = 0;

    if ( isAskForHelp(argc, argv) )
    {
        printHelp();
        return 0;
    }

    if ( !parseArgs(argc, argv, &params) )
    {
        printUsage();
        return 0;
    }

    if ( !checkArgs(&params) )
    {
        printUsage();
        return 0;
    }

    if ( params.Flags & FLAG_DECODE )
    {
        if ( params.InPath )
        {
            s = B64_decodeFile(params.InPath, &buffer, &bufferSize);
            if ( s != 0 )
            {
                EPrint("B64_decode failed! (0x%x)", s);
                goto clean;
            }
        }
        else
        {
            s = B64_decode((PUINT8)params.Bytes, params.BytesSize, &buffer, &bufferSize);
            if ( s != 0 )
            {
                EPrint("B64_decode failed! (0x%x)", s);
                goto clean;
            }
        }

        printResult("Decoded", params.Flags, buffer, bufferSize);

        if ( params.OutPath )
        {
            s = writeResult(params.OutPath, buffer, bufferSize);
            if ( s != 0 )
            {
                EPrint("writeResult failed! (0x%x)", s);
                goto clean;
            }
        }
    }
    else if ( params.Flags & FLAG_ENCODE )
    {
        ULONG encodeFlags = (params.Flags&FLAG_CRLF) ? 0 :
                            (params.Flags&FLAG_LF) ? CRYPT_STRING_NOCR : 
                            CRYPT_STRING_NOCRLF;

        if ( params.InPath )
        {
            s = B64_encodeFile(params.InPath, &buffer, &bufferSize, encodeFlags);
            if ( s != 0 )
            {
                EPrint("B64_encodeFile failed! (0x%x)", s);
                goto clean;
            }
        }
        else
        {
            s = B64_encode(params.Bytes, params.BytesSize, &buffer, &bufferSize, encodeFlags);
            if ( s != 0 )
            {
                EPrint("B64_encode failed! (0x%x)", s);
                goto clean;
            }
        }

        printResult("Encoded", params.Flags, buffer, bufferSize);
        
        if ( params.OutPath )
        {
            s = writeResult(params.OutPath, buffer, bufferSize);
            if ( s != 0 )
            {
                EPrint("writeResult failed! (0x%x)", s);
                goto clean;
            }
        }
    }

clean:
    if ( params.InPath )
        free(params.InPath);
    if ( params.OutPath )
        free(params.OutPath);
    if ( (params.Flags & FLAG_BYTES_ALLOC) && params.Bytes )
        free(params.Bytes);
    if ( buffer )
        free(buffer);

    return s;
}

VOID printResult(_In_ PCHAR Label, _In_ ULONG Flags, _In_ PVOID Buffer, _In_ ULONG BufferSize)
{
    if ( ! (Flags&(FLAG_PRINT_RESULT_A|FLAG_PRINT_RESULT_B|FLAG_PRINT_RESULT_8|FLAG_PRINT_RESULT_16|FLAG_PRINT_RESULT_32|FLAG_PRINT_RESULT_64) ) )
        return;

    printf("%s bytes (0x%x):\n", Label, BufferSize);
    if ( Flags & FLAG_PRINT_RESULT_A )
    {
        printf("%.*s\n", BufferSize, (PCHAR)Buffer);
        printf("\n");
    }
    if ( Flags & FLAG_PRINT_RESULT_B )
    {
        PrintMemBytes(Buffer, BufferSize);
        printf("\n");
    }
    if ( Flags & FLAG_PRINT_RESULT_8 )
    {
        PrintMemCols8(Buffer, BufferSize);
        printf("\n");
    }
    if ( Flags & FLAG_PRINT_RESULT_16 )
    {
        PrintMemCols16(Buffer, BufferSize);
        printf("\n");
    }
    if ( Flags & FLAG_PRINT_RESULT_32 )
    {
        PrintMemCols32(Buffer, BufferSize);
        printf("\n");
    }
    if ( Flags & FLAG_PRINT_RESULT_64 )
    {
        PrintMemCols64(Buffer, BufferSize);
        printf("\n");
    }
}

INT writeResult(_In_ PWCHAR Path, _In_ PVOID Buffer, _In_ ULONG BufferSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE file = NULL;
    
    ULONG bytesWritten;
    IO_STATUS_BLOCK iosb = {0};

    status = ntOpenFile(Path, &file, NT_FILE_WRITE_ACCESS, FILE_OVERWRITE_IF);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Could not open file \"%ws\"! (0x%x)\n", Path, status);
        goto clean;
    }

    status = NtWriteFile(file, NULL, NULL, NULL, &iosb, Buffer, BufferSize, NULL, NULL);
    if ( status != 0 )
    {
        EPrint("NtWriteFile failed! (0x%x)\n", status);
        goto clean;
    }
    
    bytesWritten = (ULONG) iosb.Information;
    printf("0x%x bytes written to %ws\n", bytesWritten, &Path[4]);

clean:
    if (file)
        NtClose(file);

    return status;
}

BOOL parseArgs(_In_ INT argc, _In_reads_(argc) CHAR** argv, _Out_ PCMD_PARAMS Params)
{
    INT s = 0;
    INT i;

    PCHAR arg = NULL;
    PCHAR val1 = NULL;

    // defaults
    memset(Params, 0, sizeof(*Params));
    
    for ( i = 1; i < argc; i++ )
    {
        arg = argv[i];
        val1 = GET_ARG_VALUE(argc, argv, i, 1);

        if ( IS_1C_ARG(arg, 'd') )
        {
            Params->Flags |= FLAG_DECODE;
        }
        else if ( IS_1C_ARG(arg, 'e') )
        {
            Params->Flags |= FLAG_ENCODE;
        }
        else if ( IS_2C_ARG(arg, 'ip') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing path\n");
            
            s = fillNtPath(val1, &Params->InPath);
            if ( s != 0 )
                break;
            i++;
        }
        else if ( IS_2C_ARG(arg, 'op') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing path\n");
            
            s = fillNtPath(val1, &Params->OutPath);
            if ( s != 0 )
                break;
            i++;
        }
        else if ( IS_2C_ARG(arg, 'ib') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing bytes\n");
            
            s = parsePlainBytes(val1, &Params->Bytes, &Params->BytesSize, MAXUINT32);
            if ( s != 0 )
            {
                break;
            }
            Params->Flags |= FLAG_BYTES_ALLOC;
            
            i++;
        }
        else if ( IS_2C_ARG(arg, 'is') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing string\n");

            Params->Bytes = (PUINT8)val1;
            Params->BytesSize = (ULONG)strlen(val1);
            
            i++;
        }
        else if ( IS_2C_ARG(arg, 'cr') )
        {
            Params->Flags |= FLAG_CRLF;
        }
        else if ( IS_4C_ARG(arg, 'crlf') )
        {
            Params->Flags |= FLAG_CRLF;
        }
        else if ( IS_2C_ARG(arg, 'lf') )
        {
            Params->Flags |= FLAG_LF;
        }
        else if ( IS_2C_ARG(arg, 'pa') )
        {
            Params->Flags |= FLAG_PRINT_RESULT_A;
        }
        else if ( IS_2C_ARG(arg, 'pb') )
        {
            Params->Flags |= FLAG_PRINT_RESULT_B;
        }
        else if ( IS_3C_ARG(arg, 'pc8') )
        {
            Params->Flags |= FLAG_PRINT_RESULT_8;
        }
        else if ( IS_4C_ARG(arg, 'pc16') )
        {
            Params->Flags |= FLAG_PRINT_RESULT_16;
        }
        else if ( IS_4C_ARG(arg, 'pc32') )
        {
            Params->Flags |= FLAG_PRINT_RESULT_32;
        }
        else if ( IS_4C_ARG(arg, 'pc64') )
        {
            Params->Flags |= FLAG_PRINT_RESULT_64;
        }
        else if ( IS_1C_ARG(arg, 'v') )
        {
            Params->Flags |= FLAG_VERBOSE;
        }
        else
        {
            printf("INFO: Unknown arg type \"%s\"\n", arg);
        }
    }

    if ( Params->OutPath == NULL && !(Params->Flags&FLAG_PRINT_RESULT) )
        Params->Flags |= FLAG_PRINT_RESULT_A;
    
    if ( Params->Flags&FLAG_VERBOSE )
    {
        printf("mode: %s\n", (Params->Flags&FLAG_DECODE)?"Decode"
                            :(Params->Flags&FLAG_ENCODE)?"Encode"
                            :"None");
        printf("Input: ");
        if ( Params->InPath != NULL )
            printf("%ws\n", &Params->InPath[4]);
        else if ( Params->Bytes != NULL )
            printf("%s\n", (PCHAR)Params->Bytes);
        else
            printf("None\n");
        if ( Params->OutPath != NULL )
            printf("OutPath: %ws\n", &Params->OutPath[4]);
        printf("Print Result: %s\n", (Params->Flags&FLAG_PRINT_RESULT)?"True":"False");

        printf("\n");
    }

//clean:

    return s == 0;
}

BOOL checkArgs(_In_ PCMD_PARAMS Params)
{
    INT s = 0;
    ULONG f = Params->Flags&(FLAG_ENCODE|FLAG_DECODE);
    if ( ( (f & (f-1)) != 0 ) )
    {
        EPrint("More than one mode selected!\n");
        s = -1;
    }
    else if ( f == 0 )
    {
        EPrint("No mode selected!\n");
        s = -1;
    }

    if ( Params->Flags & FLAG_DECODE )
    {
        if (Params->InPath == NULL && Params->Bytes == NULL )
        {
            EPrint("Got nothing to decode!\n");
            s = -1;
        }
        else if ( Params->InPath != NULL && Params->Bytes != NULL )
        {
            EPrint("Can only decode file or bytes!\n");
            s = -1;
        }
    }

    if ( Params->Flags & FLAG_ENCODE )
    {
        if ( Params->InPath == NULL && Params->Bytes == NULL )
        {
            EPrint("Got nothing to encode!\n");
            s = -1;
        }
        else if ( Params->InPath != NULL && Params->Bytes != NULL )
        {
            EPrint("Can only encode file or bytes!\n");
            s = -1;
        }
    }

#ifdef ERROR_PRINT
    if ( s != 0 )
        printf("\n");
#endif

    return s == 0;
}

void printVersion()
{
    printf("%s\n", BN);
    printf("Version: %s\n", VS);
    printf("Last changed: %s\n", LC);
    printf("Compiled: %s %s\n", __DATE__, __TIME__);
}

void printUsage()
{
    printf("Usage: %s [/d] [/e] [/ip <path>] [/op <path>] [/is <string|base64>]\n", BN);
}

void printHelp()
{
    printVersion();
    printf("\n");
    printUsage();
    printf("\n");
    printf("Modes:\n");
    printf(" /d: Decode base64 string into bytes.\n");
    printf(" /e: Encode bytes into base64 string.\n");
    printf("Input:\n");
    printf(" /ib: Input bytes as hex string. If set it's the source of /e or /d.\n");
    printf(" /is: Input string. If set it's the source of /e or /d.\n");
    printf(" /ip: Path to a file. If set it's the source of /e or /d.\n");
    printf("Format:\n");
    printf(" /cr: Insert line feeds (LF / 0x0A) into encoded string.\n");
    printf(" /crlf: Insert carriage return/line feed (CR LF / 0x0D 0x0A) into encoded string.\n");
    printf("Output:\n");
    printf(" /op: Path to a file. If set the result of /e or /d will be written to it.\n");
    printf(" /p*: Print result of /e or /d even if /op is set.\n");
    printf("   /pa: Print as ascii string (default).\n");
    printf("   /pb: Print in plain bytes.\n");
    printf("   /pc8: Print in cols of Address | bytes | ascii chars.\n");
    printf("   /pc16: Print in cols of Address | words | utf-16 chars.\n");
    printf("   /pc32: Print in cols of Address | dwords.\n");
    printf("   /pc64: Print in cols of Address | qwords.\n");
    printf("Other:\n");
    printf(" /h: Print this\n");
}
