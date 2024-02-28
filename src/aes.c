#include "aes.h"

#include <strsafe.h>

#include <stdio.h>
#include <stdlib.h>

#include "inc/nt.h"
#include "shared/print.h"
#include "shared/Converter.h"
#include "shared/Args.h"
#include "files/FilesW.h"

#include "shared/argParsing.h"

#include "crypto/AESCNG.h"
#include "crypto/HasherCNG.h"
#include "crypto/BRand.h"


#define BN "AES"
#define VS "1.0.0"
#define LC "01.06.2023"

#define FLAG_VERBOSE               (0x1)
#define FLAG_DECODE                (0x2)
#define FLAG_ENCODE                (0x4)
#define FLAG_BYTES_ALLOC           (0x8)
#define FLAG_PRINT_RESULT_A       (0x10)
#define FLAG_PRINT_RESULT_U       (0x20)
#define FLAG_PRINT_RESULT_B       (0x40)
#define FLAG_PRINT_RESULT_8       (0x80)
#define FLAG_PRINT_RESULT_16     (0x100)
#define FLAG_PRINT_RESULT_32     (0x200)
#define FLAG_PRINT_RESULT_64     (0x400)
#define FLAG_IV_SET              (0x800)
#define FLAG_PW_SET             (0x1000)

#define PRINT_RESULT (FLAG_PRINT_RESULT_A|FLAG_PRINT_RESULT_U|FLAG_PRINT_RESULT_B|FLAG_PRINT_RESULT_8|FLAG_PRINT_RESULT_16|FLAG_PRINT_RESULT_32|FLAG_PRINT_RESULT_64)

#define AES_SECRET_SIZE (0x20)

typedef struct _CMD_PARAMS {
    PUINT8 Bytes;
    ULONG BytesSize;
    UINT32 Flags;
    PWCHAR InPath;
    PWCHAR OutPath;
    UINT8 Secret[AES_SECRET_SIZE];
    UINT8 IV[AES_IV_SIZE];
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
    ULONG bufferSize;

    AES_CTXT aesCtxt = {0};

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

    s = AES_init(&aesCtxt);
    if ( s != 0 )
    {
        EPrint("AES_init failed! (0x%x)\n", s);
        goto clean;
    }

    s = AES_generateKey(&aesCtxt, params.Secret, AES_SECRET_SIZE);
    if ( s != 0 )
    {
        EPrint("AES_generateKey failed! (0x%x)\n", s);
        goto clean;
    }

    if ( params.Flags & FLAG_DECODE )
    {
        s = AES_decrypt(&aesCtxt, params.Bytes, params.BytesSize, &buffer, &bufferSize, params.IV, AES_IV_SIZE);
        if ( s != 0 )
        {
            EPrint("Decryption failed! (0x%x)", s);
            goto clean;
        }

        printResult("Decrypted", params.Flags, buffer, bufferSize);

        if ( params.OutPath )
        {
            s = writeResult(params.OutPath, buffer, bufferSize);
            if ( s != 0 )
            {
                EPrint("Writing result failed! (0x%x)", s);
                goto clean;
            }
        }
    }
    else if ( params.Flags & FLAG_ENCODE )
    {
        s = AES_encrypt(&aesCtxt, params.Bytes, params.BytesSize, &buffer, &bufferSize, params.IV, AES_IV_SIZE);
        if ( s != 0 )
        {
            EPrint("Encrypting failed! (0x%x)", s);
            goto clean;
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
    AES_clean(&aesCtxt);

    return s;
}

VOID printResult(_In_ PCHAR Label, _In_ ULONG Flags, _In_ PVOID Buffer, _In_ ULONG BufferSize)
{
    if ( ! (Flags&PRINT_RESULT) )
        return;

    printf("%s bytes (0x%x):\n", Label, BufferSize);
    if ( Flags & FLAG_PRINT_RESULT_A )
    {
        printf("%.*s\n", BufferSize, (PCHAR)Buffer);
        printf("\n");
    }
    if ( Flags & FLAG_PRINT_RESULT_U )
    {
        wprintf(L"%.*ws\n", BufferSize/2, (PWCHAR)Buffer);
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
    
    ULONG cch;
    ULONG cb;
    ULONG size;

    PWCHAR valW = NULL;
    PUINT8 ptr = NULL;

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
        else if ( IS_2C_ARG(arg, 'if') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing path\n");
            if ( Params->BytesSize != 0 )
            {
                DPrint("Bytes already set. Skipping!\n");
                i++;
                continue;
            }
            
            s = fillNtPath(val1, &Params->InPath);
            if ( s != 0 )
                break;
            
            s = ntGetFileBytes(Params->InPath, &Params->Bytes, &Params->BytesSize);
            if ( s != 0 )
            {
                EPrint("Reading file bytes failed! (0x%x)\n", s);
                break;
            }

            i++;
        }
        else if ( IS_2C_ARG(arg, 'of') )
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
            if ( Params->BytesSize != 0 )
            {
                DPrint("Bytes already set. Skipping!\n");
                i++;
                continue;
            }
            s = parsePlainBytes(val1, &Params->Bytes, &Params->BytesSize, MAXUINT32);
            if ( s != 0 )
            {
                break;
            }
            Params->Flags |= FLAG_BYTES_ALLOC;
            
            i++;
        }
        else if ( IS_2C_ARG(arg, 'ia') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing string\n");
            if ( Params->BytesSize != 0 )
            {
                DPrint("Bytes already set. Skipping!\n");
                i++;
                continue;
            }

            Params->Bytes = (PUINT8)val1;
            Params->BytesSize = (ULONG)strlen(val1);
            
            i++;
        }
        else if ( IS_2C_ARG(arg, 'iu') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing string\n");
            if ( Params->BytesSize != 0 )
            {
                DPrint("Bytes already set. Skipping!\n");
                i++;
                continue;
            }

            cch = (ULONG)strlen(val1);
            cb = cch * 2;

            Params->Bytes = malloc(cb + 2);
            if ( !Params->Bytes )
            {
                s = GetLastError();
                EPrint("No memory! (0x%x)\n", s);
                break;
            }

            StringCchPrintfW((PWCHAR)Params->Bytes, cch + 1, L"%hs", val1);
            Params->BytesSize = cb + 2;

            Params->Flags |= FLAG_BYTES_ALLOC;

            i++;
        }
        else if ( IS_3C_ARG(arg, 'ivb') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing bytes\n");
            if ( Params->Flags & FLAG_IV_SET )
            {
                DPrint("IV already set. Skipping!\n");
                i++;
                continue;
            }
            
            size = (ULONG)strlen(val1);
            if ( size != AES_IV_SIZE * 2 )
            {
                EPrint("Initial vector bytes have to be 0x10 in size!\n");
                s = ERROR_INVALID_PARAMETER;
                break;
            }
            size = AES_IV_SIZE;

            ptr = Params->IV;
            s = parsePlainBytes(val1, &ptr, &size, AES_IV_SIZE);
            if ( s != 0 )
            {
                break;
            }
            
            Params->Flags |= FLAG_IV_SET;
            
            i++;
        }
        else if ( IS_3C_ARG(arg, 'iva') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing string\n");
            if ( Params->Flags & FLAG_IV_SET )
            {
                DPrint("IV already set. Skipping!\n");
                i++;
                continue;
            }

            s = md5Buffer((PUINT8)val1, (ULONG)strlen(val1), (PUINT8)Params->IV, AES_IV_SIZE);
            if ( s != 0 )
            {
                EPrint("md5 calculation of iv failed! (0x%x)\n", s);
                break;
            }
            
            Params->Flags |= FLAG_IV_SET;

            i++;
        }
        else if ( IS_3C_ARG(arg, 'ivu') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing string\n");
            if ( Params->Flags & FLAG_IV_SET )
            {
                DPrint("IV already set. Skipping!\n");
                i++;
                continue;
            }

            cch = (ULONG)strlen(val1);
            cb = cch * 2;

            if ( valW )
                free(valW);

            valW = NULL;
            valW = malloc(cb + 2);
            if ( !valW )
            {
                s = GetLastError();
                EPrint("No memory! (0x%x)\n", s);
                break;
            }

            StringCchPrintfW(valW, cch + 1, L"%hs", val1);
            s = md5Buffer((PUINT8)valW, cb, (PUINT8)Params->IV, AES_IV_SIZE);
            if ( s != 0 )
            {
                EPrint("md5 calculation of iv failed! (0x%x)\n", s);
                break;
            }
            
            Params->Flags |= FLAG_IV_SET;

            i++;
        }
        else if ( IS_3C_ARG(arg, 'pwb') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing bytes\n");
            if ( Params->Flags & FLAG_PW_SET )
            {
                DPrint("PW already set. Skipping!\n");
                i++;
                continue;
            }
            
            size = (ULONG)strlen(val1);
            if ( size != AES_SECRET_SIZE * 2 )
            {
                EPrint("Password bytes have to be 0x20 in size!\n");
                s = ERROR_INVALID_PARAMETER;
                break;
            }
            size = AES_SECRET_SIZE;
            
            ptr = Params->Secret;
            s = parsePlainBytes(val1, &ptr, &size, AES_SECRET_SIZE);
            if ( s != 0 )
            {
                break;
            }
            
            Params->Flags |= FLAG_PW_SET;
            
            i++;
        }
        else if ( IS_3C_ARG(arg, 'pwa') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing string\n");
            if ( Params->Flags & FLAG_PW_SET )
            {
                DPrint("PW already set. Skipping!\n");
                i++;
                continue;
            }

            s = sha256Buffer((PUINT8)val1, (ULONG)strlen(val1), (PUINT8)Params->Secret, AES_SECRET_SIZE);
            if ( s != 0 )
            {
                EPrint("sha256 calculation of pw failed! (0x%x)\n", s);
                break;
            }
            
            Params->Flags |= FLAG_PW_SET;

            i++;
        }
        else if ( IS_3C_ARG(arg, 'pwu') )
        {
            BREAK_ON_NOT_A_VALUE(val1, s, "missing string\n");
            if ( Params->Flags & FLAG_PW_SET )
            {
                DPrint("PW already set. Skipping!\n");
                i++;
                continue;
            }

            cch = (ULONG)strlen(val1);
            cb = cch * 2;

            if ( valW )
                free(valW);

            valW = NULL;
            valW = malloc(cb + 2);
            if ( !valW )
            {
                s = GetLastError();
                EPrint("No memory! (0x%x)\n", s);
                break;
            }

            StringCchPrintfW(valW, cch + 1, L"%hs", val1);
            s = sha256Buffer((PUINT8)valW, cb, (PUINT8)Params->Secret, AES_SECRET_SIZE);
            if ( s != 0 )
            {
                EPrint("sha256 calculation of pw failed! (0x%x)\n", s);
                break;
            }
            
            Params->Flags |= FLAG_PW_SET;

            i++;
        }
        else if ( IS_2C_ARG(arg, 'pa') )
        {
            Params->Flags |= FLAG_PRINT_RESULT_A;
        }
        else if ( IS_2C_ARG(arg, 'pu') )
        {
            Params->Flags |= FLAG_PRINT_RESULT_U;
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
    

    if ( s != 0 )
    {
#ifdef ERROR_PRINT
        printf("\n");
#endif
        goto clean;
    }

    if ( Params->OutPath == NULL && !(Params->Flags&PRINT_RESULT) )
        Params->Flags |= FLAG_PRINT_RESULT_8;
    
    if ( Params->Flags & FLAG_ENCODE )
    {
        if ( !(Params->Flags & FLAG_IV_SET) )
        {
            if ( Params->Flags&FLAG_VERBOSE ) {
                DPrint("Initial vector not set. Generating random IV.\n"); }
            s = generateRand(Params->IV, AES_IV_SIZE);
            if ( s != 0 )
            {
                EPrint("Random iv generation failed! (0x%x)\n", s);
                goto clean;
            }
            Params->Flags |= FLAG_IV_SET;
            printf("Generated random initial vector:\n");
            PrintMemBytes(Params->IV, AES_IV_SIZE);
        }
        if ( ! (Params->Flags & FLAG_PW_SET) )
        {
            if ( Params->Flags&FLAG_VERBOSE ) {
                DPrint("Password not set. Generating random secret.\n"); }
            s = generateRand(Params->Secret, AES_SECRET_SIZE);
            if ( s != 0 )
            {
                EPrint("Random password generation failed! (0x%x)\n", s);
                goto clean;
            }
            Params->Flags |= FLAG_PW_SET;
            printf("Generated random secret:\n");
            PrintMemBytes(Params->Secret, AES_SECRET_SIZE);
        }
    }

    if ( Params->Flags&FLAG_VERBOSE )
    {
        printf("mode: %s\n", (Params->Flags&FLAG_DECODE)?"Decrypt"
                            :(Params->Flags&FLAG_ENCODE)?"Encrypt"
                            :"None");
        printf("Input: ");
        if ( Params->InPath != NULL )
            printf("%ws\n", &Params->InPath[4]);
        else if ( Params->Bytes != NULL ) {
            PrintMemCols8(Params->Bytes, Params->BytesSize); }
        else
            printf("None\n");
        if ( Params->OutPath != NULL )
            printf("OutPath: %ws\n", &Params->OutPath[4]);
        printf("Print Result: %s\n", (Params->Flags&PRINT_RESULT)?"True":"False");

        printf("\n");
    }

clean:
    if ( valW )
        free(valW);

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
        if ( Params->Bytes == NULL )
        {
            EPrint("Got nothing to decode!\n");
            s = -1;
        }
        if ( ! (Params->Flags & FLAG_IV_SET) )
        {
            EPrint("Initial vector is required for decoding!\n");
            s = -1;
        }
        if ( ! (Params->Flags & FLAG_PW_SET) )
        {
            EPrint("Password is required for decoding!\n");
            s = -1;
        }
    }

    if ( Params->Flags & FLAG_ENCODE )
    {
        if ( Params->Bytes == NULL )
        {
            EPrint("Got nothing to encode!\n");
            s = -1;
        }
        if ( ! (Params->Flags & FLAG_IV_SET) )
        {
            EPrint("Initial vector is required for encoding!\n");
            s = -1;
        }
        if ( ! (Params->Flags & FLAG_PW_SET) )
        {
            EPrint("Password is required for encoding!\n");
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
    printf("Usage: %s [/d|/e] [/ia|/iu|/ib|/if <value>] [/of <path>] [/pwa|/pwu|/pwb] [/iva|/ivu|/ivb] [/p*] [/v] [/h]\n", BN);
}

void printHelp()
{
    printVersion();
    printf("\n");
    printUsage();
    printf("\n");
    printf("Modes:\n");
    printf(" /d: Decode aes cypher into plain bytes.\n");
    printf(" /e: Encode bytes into aes cypher.\n");
    printf("Password:\n");
    printf(" /pwa: Ascii password string of which the sha256 hash will be calculated and used as the secret.\n");
    printf(" /pwu: Unicode (utf-16) password string of which the sha256 will be calculated and used as the secret.\n");
    printf(" /pwb: 0x20 hex bytes used directly as the secret.\n");
    printf(" :: If no password is given, a random one will be generated. This obviously only works while encoding.\n");
    printf("Initial vector:\n");
    printf(" /iva: Ascii initial vector string of which the md5 hash will be calculated and used as the iv.\n");
    printf(" /ivu: Unicode (utf-16) initial vector string of which the md5 hash will be calculated and used as the iv.\n");
    printf(" /ivb: 0x10 hex bytes used directly as the iv.\n");
    printf(" :: If no initial vector is given, a random one will be generated. This obviously only works while encoding.\n");
    printf("Input:\n");
    printf(" /ib: Input bytes as hex string. If set it's the source of /e or /d.\n");
    printf(" /ia: Input ascii string. If set it's the source of /e.\n");
    printf(" /iu: Input unicode string. If set it's the source of /e.\n");
    printf(" /if: Path to a file. If set it's the source of /e or /d.\n");
    printf("Output:\n");
    printf(" /of: Path to a file. If set the result of /e or /d will be written to it.\n");
    printf(" /p*: Print result of /e or /d even if /of is set.\n");
    printf("   /pa: Print as ascii string.\n");
    printf("   /pb: Print in plain bytes (default).\n");
    printf("   /pc8: Print in cols of Address | bytes | ascii chars.\n");
    printf("   /pc16: Print in cols of Address | words | utf-16 chars.\n");
    printf("   /pc32: Print in cols of Address | dwords.\n");
    printf("   /pc64: Print in cols of Address | qwords.\n");
    printf("Other:\n");
    printf(" /v: More verbose\n");
    printf(" /h: Print this\n");
}
