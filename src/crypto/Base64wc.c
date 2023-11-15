#include "Base64wc.h"
#include "../files/FilesW.h"

#include <wincrypt.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "../shared/print.h"


#ifdef RING3
#define ExAllocatePoolWithTag(_pt_, _n_, _t_) malloc(_n_)
#define ExFreePoolWithTag(_p_, _t_) free(_p_)
#define ExFreePool(_p_) free(_p_)
#endif


NTSTATUS B64_encodeFile(
    _In_ PWCHAR Path, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize,
    _In_ ULONG Flags
)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE file = NULL;
    UINT64 fileSize = 0;
    PUINT8 fileBuffer = NULL;
    
    ULONG bytesRead;
    IO_STATUS_BLOCK iosb = {0};


    status = ntOpenFile(Path, &file, NT_FILE_READ_ACCESS, 0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Could not open file \"%ws\"! (0x%x)\n", Path, status);
        goto clean;
    }

    status = ntGetFileSize(file, &fileSize);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("GetFileSize for \"%ws\" failed! (0x%x)\n", Path, status);
        goto clean;
    }
    if ( fileSize >= (ULONG)-1 )
    {
        status = STATUS_BUFFER_TOO_SMALL;
        EPrint("File \"%ws\" too big! (0x%x)\n", Path, status);
        goto clean;
    }

    fileBuffer = (PUINT8)ExAllocatePoolWithTag(PagedPool, fileSize, 'hsah');
    if ( fileBuffer == NULL )
    {
        status = STATUS_NO_MEMORY;
        EPrint("Allocating buffer failed! (0x%x)\n", status);
        goto clean;
    }


    status = NtReadFile(file, NULL, NULL, NULL, &iosb, fileBuffer, (ULONG)fileSize, NULL, NULL);
    if ( status != 0 )
    {
        EPrint("NtReadFile failed! (0x%x)\n", status);
        goto clean;
    }
    
    bytesRead = (ULONG) iosb.Information;

    status = B64_encode(fileBuffer, bytesRead, Output, OutputSize, Flags);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("B64_encode failed! (0x%x)\n", status);
        goto clean;
    }


clean:
    if (file)
        NtClose(file);
    if (fileBuffer)
        ExFreePool(fileBuffer);

    return status;
}


NTSTATUS B64_decodeFile(
    _In_ PWCHAR Path, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    HANDLE file = NULL;
    UINT64 fileSize = 0;
    PUINT8 fileBuffer = NULL;

    ULONG bytesRead;
    IO_STATUS_BLOCK iosb = {0};

    status = ntOpenFile(Path, &file, NT_FILE_READ_ACCESS, 0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Could not open file \"%ws\"! (0x%x)\n", Path, status);
        goto clean;
    }

    status = ntGetFileSize(file, &fileSize);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("GetFileSize for \"%ws\" failed! (0x%x)\n", Path, status);
        goto clean;
    }
    if ( fileSize >= (ULONG)-1 )
    {
        status = STATUS_BUFFER_TOO_SMALL;
        EPrint("File \"%ws\" too big! (0x%x)\n", Path, status);
        goto clean;
    }

    fileBuffer = (PUINT8)ExAllocatePoolWithTag(PagedPool, fileSize, 'hsah');
    if ( fileBuffer == NULL )
    {
        status = STATUS_NO_MEMORY;
        EPrint("Allocating buffer failed! (0x%x)\n", status);
        goto clean;
    }


    status = NtReadFile(file, NULL, NULL, NULL, &iosb, fileBuffer, (ULONG)fileSize, NULL, NULL);
    if ( status != 0 )
    {
        EPrint("NtReadFile failed! (0x%x)\n", status);
        goto clean;
    }
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Reading bytes failed! (0x%x)\n", status);
        goto clean;
    }
    
    bytesRead = (ULONG) iosb.Information;

    
    status = B64_decode(fileBuffer, bytesRead, Output, OutputSize);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("B64_decode failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if ( file )
        NtClose(file);
    if ( fileBuffer )
        ExFreePool(fileBuffer);

    return status;
}


NTSTATUS B64_encode(
    _In_ PUINT8 Input, 
    _In_ ULONG InputSize, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize,
    _In_ ULONG Flags
)
{
    int s = 0;
    BOOL b;
    ULONG req = 0;
    ULONG flags = CRYPT_STRING_BASE64 | Flags;

    b = CryptBinaryToStringA(
            Input,
            InputSize,
            flags,
            NULL,
            &req
        );
    if ( !b )
    {
        s = GetLastError();
        EPrint("CryptBinaryToStringA failed! (0x%x)\n", s);
        goto clean;
    }

    if ( *Output == NULL )
    {
        *Output = (PUINT8)malloc(req);
        if ( *Output == NULL )
        {
            s = GetLastError();
            EPrint("malloc failed! (0x%x)\n", s);
            goto clean;
        }
    }
    else
    {
        if ( *OutputSize < req )
        {
            s = ERROR_BUFFER_OVERFLOW;
            EPrint("Output[0x%x] too small! 0x%x needed. (0x%x)\n", *OutputSize, req, s);
            goto clean;
        }
    }

    b = CryptBinaryToStringA(
            Input,
            InputSize,
            flags,
            (PCHAR)*Output,
            &req
        );
    if ( !b )
    {
        s = GetLastError();
        EPrint("CryptBinaryToStringA failed! (0x%x)\n", s);
        goto clean;
    }

    *OutputSize = req;

clean:
    ;

    return s;
}

NTSTATUS B64_decode(
    _In_ PUINT8 Input, 
    _In_ ULONG InputSize, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize
)
{
    int s = 0;
    BOOL b;
    ULONG req = 0;
    ULONG flags = CRYPT_STRING_BASE64;

    b = CryptStringToBinaryA(
            (PCHAR)Input,
            InputSize,
            flags,
            NULL,
            &req,
            0,
            NULL
        );
    if ( !b )
    {
        s = GetLastError();
        EPrint("CryptBinaryToStringA failed! (0x%x)\n", s);
        goto clean;
    }
    
    if ( *Output == NULL )
    {
        *Output = (PUINT8)malloc(req);
        if ( *Output == NULL )
        {
            s = GetLastError();
            EPrint("malloc failed! (0x%x)\n", s);
            goto clean;
        }
    }
    else
    {
        if ( *OutputSize < req )
        {
            s = ERROR_BUFFER_OVERFLOW;
            EPrint("Output[0x%x] too small! 0x%x needed. (0x%x)\n", *OutputSize, req, s);
            goto clean;
        }
    }

    b = CryptStringToBinaryA(
            (PCHAR)Input,
            InputSize,
            flags,
            *Output,
            &req,
            0,
            NULL
        );
    if ( !b )
    {
        s = GetLastError();
        EPrint("CryptBinaryToStringA failed! (0x%x)\n", s);
        goto clean;
    }

    *OutputSize = req;

clean:
    ;

    return s;
}
