#include "HasherCNG.h"
#include "../files/FilesW.h"

#define BUFFER_SIZE (0x1000)

#ifdef RING3
#include <stdio.h>
#include <stdlib.h>
#endif

#include "../shared/print.h"



#ifdef RING3
#define ExAllocatePoolWithTag(_pt_, _n_, _t_) malloc(_n_)
#define ExFreePoolWithTag(_p_, _t_) free(_p_)
#define ExFreePool(_p_) free(_p_)
#endif



static NTSTATUS createHash(
    _In_ PHashCtxt Ctxt
);

NTSTATUS hashBufferC(
    _In_ PUINT8 Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PHashCtxt Ctxt
);




__forceinline
NTSTATUS hashFileData(
    _In_ PUINT8 Buffer,
    _In_ ULONG ToRead,
    _In_ SIZE_T Offset,
    _In_ HANDLE File, 
    _In_ PHashCtxt Ctxt
)
{
    NTSTATUS status = 0;
    ULONG bytesRead;
    IO_STATUS_BLOCK iosb = {0};

    (Offset);
    status = NtReadFile(File, NULL, NULL, NULL, &iosb, Buffer, ToRead, NULL, NULL);
    if ( status != 0 )
    {
        EPrint("NtReadFile failed! (0x%x)\n", status);
        goto clean;
    }
    
    bytesRead = (ULONG) iosb.Information;
    
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Reading bytes failed (0x%x)!\n", status);
        goto clean;
    }

    status = BCryptHashData(Ctxt->Hash, Buffer, bytesRead, 0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptHashData failed (0x%x)!\n", status);
        goto clean;
    }

clean:

    return status;
}

NTSTATUS hashFileC(
    _In_ PWCHAR Path, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PHashCtxt Ctxt
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE file = NULL;
    UINT64 file_size = 0;
    PUINT8 buffer = NULL;
    size_t offset = 0;
    UINT64 parts;
    ULONG rest;
    UINT64 i;

    if ( HashBytesSize < Ctxt->HashSize )
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto clean;
    }

    status = createHash(Ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    status = ntOpenFile(Path, &file, NT_FILE_READ_ACCESS, 0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Could not open file \"%ws\"! (0x%x)\n", Path, status);
        goto clean;
    }

    status = ntGetFileSize(file, &file_size);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("GetFileSize for \"%ws\" failed! (0x%x)\n", Path, status);
        goto clean;
    }

    buffer = (PUINT8)ExAllocatePoolWithTag(PagedPool, BUFFER_SIZE, 'hsah');
    if ( buffer == NULL )
    {
        status = STATUS_NO_MEMORY;
        EPrint("Allocating hash buffer failed! (0x%x)\n", status);
        goto clean;
    }

    parts = file_size / BUFFER_SIZE;
    rest = (ULONG)(file_size % BUFFER_SIZE);
    for ( i = 0; i < parts; i++ )
    {
        status = hashFileData(buffer, BUFFER_SIZE, offset, file, Ctxt);
        if ( !NT_SUCCESS(status) )
        {
            EPrint("hashFileData failed! (0x%x)\n", status);
            goto clean;
        }

        offset += BUFFER_SIZE;
    }
    if ( rest != 0 )
    {
        status = hashFileData(buffer, rest, offset, file, Ctxt);
        if ( !NT_SUCCESS(status) )
        {
            EPrint("hashFileData failed! (0x%x)\n", status);
            goto clean;
        }
    }

    // close the hash
    status = BCryptFinishHash(Ctxt->Hash, HashBytes, Ctxt->HashSize, 0);
    if (!NT_SUCCESS(status))
    {
        EPrint("BCryptFinishHash failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if (file)
        NtClose(file);
    if (buffer)
        ExFreePool(buffer);

    return status;
}

NTSTATUS hashBufferC(
    _In_ PUINT8 Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PHashCtxt Ctxt
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    SIZE_T parts;
    ULONG rest;
    SIZE_T i;
    SIZE_T offset;

    if ( HashBytesSize < Ctxt->HashSize )
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto clean;
    }

    status = createHash(Ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    offset = 0;
    parts = BufferSize / ULONG_MAX;
    rest = (ULONG)(BufferSize % ULONG_MAX);

    for ( i = 0; i < parts; i++ )
    {
        status = BCryptHashData(Ctxt->Hash, &Buffer[offset], (ULONG)ULONG_MAX, 0);
        if ( !NT_SUCCESS(status) )
        {
            EPrint("BCryptHashData failed! (0x%x)\n", status);
            goto clean;
        }
        offset += ULONG_MAX;
    }
    if ( rest != 0 )
    {
        status = BCryptHashData(Ctxt->Hash, &Buffer[offset], rest, 0);
        if ( !NT_SUCCESS(status) )
        {
            EPrint("BCryptHashData failed! (0x%x)\n", status);
            goto clean;
        }
    }

    // close the hash
    status = BCryptFinishHash(Ctxt->Hash, HashBytes, Ctxt->HashSize, 0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptFinishHash failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    ;

    return status;
}


NTSTATUS sha256File(_In_ PWCHAR Path, _Out_ PUINT8 HashBytes, _In_ UINT16 HashBytesSize)
{
    Sha256Ctxt ctxt;
    NTSTATUS status = 0;

    status = initSha256(&ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    status = sha256FileC(Path, HashBytes, HashBytesSize, &ctxt);

clean:
    cleanSha256(&ctxt);

    return status;
}

NTSTATUS sha256FileC(_In_ PWCHAR Path, _Out_ PUINT8 HashBytes, _In_ UINT16 HashBytesSize, _In_ PSha256Ctxt Ctxt)
{
    return hashFileC(Path, HashBytes, HashBytesSize, Ctxt);
}

NTSTATUS sha256Buffer(
    _In_ PUINT8 Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
)
{
    Sha256Ctxt ctxt;
    NTSTATUS status = 0;

    status = initSha256(&ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    status = sha256BufferC(Buffer, BufferSize, HashBytes, HashBytesSize, &ctxt);

clean:
    cleanSha256(&ctxt);

    return status;
}

NTSTATUS sha256BufferC(
    _In_ PUINT8 Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PSha256Ctxt Ctxt
)
{
    return hashBufferC(Buffer, BufferSize, HashBytes, HashBytesSize, Ctxt);
}

NTSTATUS sha1File(_In_ PWCHAR Path, _Out_ PUINT8 HashBytes, _In_ UINT16 HashBytesSize)
{
    Sha1Ctxt ctxt;
    NTSTATUS status = 0;

    status = initSha1(&ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    status = sha1FileC(Path, HashBytes, HashBytesSize, &ctxt);

clean:
    cleanSha1(&ctxt);

    return status;
}

NTSTATUS sha1FileC(_In_ PWCHAR Path, _Out_ PUINT8 HashBytes, _In_ UINT16 HashBytesSize, _In_ PSha1Ctxt Ctxt)
{
    return hashFileC(Path, HashBytes, HashBytesSize, Ctxt);
}

NTSTATUS sha1Buffer(
    _In_ PUINT8 Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
)
{
    Sha1Ctxt ctxt;
    NTSTATUS status = 0;

    status = initSha1(&ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    status = sha1BufferC(Buffer, BufferSize, HashBytes, HashBytesSize, &ctxt);

clean:
    cleanSha1(&ctxt);

    return status;
}

NTSTATUS sha1BufferC(
    _In_ PUINT8 Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PSha1Ctxt Ctxt
)
{
    return hashBufferC(Buffer, BufferSize, HashBytes, HashBytesSize, Ctxt);
}

NTSTATUS md5File(_In_ PWCHAR Path, _Out_ PUINT8 HashBytes, _In_ UINT16 HashBytesSize)
{
    Md5Ctxt ctxt;
    NTSTATUS status = 0;

    status = initMd5(&ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    status = md5FileC(Path, HashBytes, HashBytesSize, &ctxt);

clean:
    cleanMd5(&ctxt);

    return status;
}

NTSTATUS md5FileC(_In_ PWCHAR Path, _Out_ PUINT8 HashBytes, _In_ UINT16 HashBytesSize, _In_ PMd5Ctxt Ctxt)
{
    return hashFileC(Path, HashBytes, HashBytesSize, Ctxt);
}

NTSTATUS md5Buffer(
    _In_ PUINT8 Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
)
{
    Md5Ctxt ctxt;
    NTSTATUS status = 0;

    status = initMd5(&ctxt);
    if ( !NT_SUCCESS(status) )
    {
        goto clean;
    }

    status = md5BufferC(Buffer, BufferSize, HashBytes, HashBytesSize, &ctxt);

clean:
    cleanMd5(&ctxt);

    return status;
}

NTSTATUS md5BufferC(
    _In_ PUINT8 Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PMd5Ctxt Ctxt
)
{
    return hashBufferC(Buffer, BufferSize, HashBytes, HashBytesSize, Ctxt);
}



NTSTATUS initMd5(_Out_ PMd5Ctxt Ctxt)
{
    return initHashCtxt(Ctxt, BCRYPT_MD5_ALGORITHM);
}

NTSTATUS initSha1(_Out_ PSha1Ctxt Ctxt)
{
    return initHashCtxt(Ctxt, BCRYPT_SHA1_ALGORITHM);
}

NTSTATUS initSha256(_Out_ PSha256Ctxt Ctxt)
{
    return initHashCtxt(Ctxt, BCRYPT_SHA256_ALGORITHM);
}

NTSTATUS initHashCtxt(_Out_ PHashCtxt Ctxt, _In_ PWCHAR AlgId)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    RtlZeroMemory(Ctxt, sizeof(HashCtxt));

    //open an algorithm handle
    status = BCryptOpenAlgorithmProvider(
        &(Ctxt->Alg),
        AlgId,
        NULL,
        0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptOpenAlgorithmProvider failed! (0x%x)\n", status);
        goto clean;
    }

    //calculate the size of the Buffer to hold the hash object
    status = BCryptGetProperty(
        Ctxt->Alg,
        BCRYPT_OBJECT_LENGTH,
        (PUINT8) &(Ctxt->HashObjectSize),
        sizeof(ULONG),
        &(Ctxt->DataSize),
        0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptGetProperty failed! (0x%x)\n", status);
        goto clean;
    }

    // allocate the hash object on the heap
    Ctxt->HashObject = (PUINT8)ExAllocatePoolWithTag(PagedPool, Ctxt->HashObjectSize, 'hsah');
    if ( NULL == Ctxt->HashObject )
    {
        status = STATUS_NO_MEMORY;
        EPrint("Memory allocation failed! (0x%x)\n", status);
        goto clean;
    }

    // calculate the length of the hash
    status = BCryptGetProperty(
        Ctxt->Alg,
        BCRYPT_HASH_LENGTH,
        (PUINT8)&(Ctxt->HashSize),
        sizeof(ULONG),
        &(Ctxt->DataSize),
        0);
    if (!NT_SUCCESS(status))
    {
        EPrint("BCryptGetProperty failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    if ( status != 0 )
        cleanHashCtxt(Ctxt);

    return status;
}

NTSTATUS createHash(_In_ PHashCtxt Ctxt)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if ( Ctxt->Hash )
    {
        BCryptDestroyHash(Ctxt->Hash);
        Ctxt->Hash = NULL;
    }

    status = BCryptCreateHash(
        Ctxt->Alg,
        &(Ctxt->Hash),
        Ctxt->HashObject,
        Ctxt->HashObjectSize,
        NULL,
        0,
        0);
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptCreateHash failed! (0x%x)\n", status);
        return status;
    }

    return status;
}

NTSTATUS cleanSha1(_Inout_ PSha1Ctxt Ctxt)
{
    return cleanHashCtxt(Ctxt);
}

NTSTATUS cleanSha256(_Inout_ PSha256Ctxt Ctxt)
{
    return cleanHashCtxt(Ctxt);
}

NTSTATUS cleanMd5(_Inout_ PMd5Ctxt Ctxt)
{
    return cleanHashCtxt(Ctxt);
}

NTSTATUS cleanHashCtxt(_Inout_ PHashCtxt Ctxt)
{
    if ( Ctxt->Alg )
    {
        BCryptCloseAlgorithmProvider(Ctxt->Alg, 0);
        Ctxt->Alg = NULL;
    }

    if ( Ctxt->Hash )
    {
        BCryptDestroyHash(Ctxt->Hash);
        Ctxt->Hash = NULL;
    }

    if ( Ctxt->HashObject )
    {
        ExFreePool(Ctxt->HashObject);
        Ctxt->HashObject = NULL;
    }

    RtlZeroMemory(Ctxt, sizeof(HashCtxt));

    return 0;
}


void hashToString(_In_ const PUINT8 hash, _In_ UINT16 hash_size, _Out_ char* output, _In_ UINT16 output_size)
{
    UINT16 i = 0;

    for (i = 0; i < hash_size; i++)
    {
        sprintf_s(output + (i * 2), output_size, "%02x", hash[i]);
    }

    output[output_size-1] = 0;
}

void printHash(_In_ const PUINT8 hash, _In_ UINT16 hash_size, _In_ const char* prefix, _In_ const char* postfix)
{
    UINT16 i = 0;

    printf("%s", prefix);
    for (i = 0; i < hash_size; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("%s", postfix);
}
