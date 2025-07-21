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

NTSTATUS ZwClose(
  _In_ HANDLE Handle
);
#endif



static NTSTATUS createHash(
    _In_ PHashCtxt ctxt
);



//
// Hashing
//

__forceinline
NTSTATUS hashFileData(
    _In_ PHashCtxt ctxt,
    _In_ PUINT8 buffer,
    _In_ ULONG to_read,
    _In_ SIZE_T offset,
    _In_ HANDLE file
)
{
    NTSTATUS status = 0;
    ULONG bytesRead;
    IO_STATUS_BLOCK iosb = {0};

    (offset);
    status = NtReadFile(file, NULL, NULL, NULL, &iosb, buffer, to_read, NULL, NULL);
    if ( status != 0 )
    {
        EPrint("NtReadFile failed! (0x%x)\n", status);
        goto clean;
    }
    bytesRead = (ULONG)iosb.Information;

    if ( status != 0 )
    {
        EPrint("Reading bytes failed (0x%x)!\n", status);
        goto clean;
    }

    status = BCryptHashData(ctxt->Hash, buffer, bytesRead, 0);
    if ( status != 0 )
    {
        EPrint("BCryptHashData failed (0x%x)!\n", status);
        goto clean;
    }
clean:
    ;

    return status;
}



//
// Arbitrary hash provider
// 

NTSTATUS hashFile(_In_ PWCHAR AlgId, _In_ PWCHAR path, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    HashCtxt ctxt;
    NTSTATUS status = 0;

    status = initHashCtxt(AlgId, 0, &ctxt);
    if ( status != 0 )
    {
        goto clean;
    }

    status = hashFileC(&ctxt, path, hash_bytes, hash_bytes_size);

clean:
    cleanHashCtxt(&ctxt);

    return status;
}

NTSTATUS hashFileC(
    _In_ PHashCtxt ctxt,
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
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

    if ( hash_bytes_size < ctxt->HashSize )
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto clean;
    }

    status = createHash(ctxt);
    if ( status != 0 )
    {
        goto clean;
    }

    status = ntOpenFile(path, &file, NT_FILE_READ_ACCESS, 0);
    if ( status != 0 )
    {
        EPrint("Could not open file \"%ws\" (0x%x)!\n", path, status);
        goto clean;
    }

    status = ntGetFileSize(file, &file_size);
    if ( status != 0 )
    {
        EPrint("ntGetFileSize for \"%ws\" failed (0x%x)!\n", path, status);
        goto clean;
    }

    buffer = (PUINT8)ExAllocatePoolWithTag(PagedPool, BUFFER_SIZE, 'hsah');
    if ( buffer == NULL )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EPrint("Allocating hash buffer failed (0x%x)!\n", status);
        goto clean;
    }

    parts = file_size / BUFFER_SIZE;
    rest = (ULONG)(file_size % BUFFER_SIZE);
    for ( i = 0; i < parts; i++ )
    {
        status = hashFileData(ctxt, buffer, BUFFER_SIZE, offset, file);
        if ( status != 0 )
        {
            EPrint("hashFileData failed (0x%x)!\n", status);
            goto clean;
        }

        offset += BUFFER_SIZE;
    }
    if ( rest != 0 )
    {
        status = hashFileData(ctxt, buffer, rest, offset, file);
        if ( status != 0 )
        {
            EPrint("hashFileData failed (0x%x)!\n", status);
            goto clean;
        }
    }

    // close the hash
    status = BCryptFinishHash(ctxt->Hash, hash_bytes, ctxt->HashSize, 0);
    if (status != 0)
    {
        EPrint("BCryptFinishHash failed (0x%x)!\n", status);
        goto clean;
    }

clean:
    if (file)
        ZwClose(file);
    if (buffer)
        ExFreePool(buffer);

    return status;
}

NTSTATUS hashBuffer(
    _In_ PWCHAR AlgId, 
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
)
{
    HashCtxt ctxt;
    NTSTATUS status = 0;

    status = initHashCtxt(AlgId, 0, &ctxt);
    if ( status != 0 )
    {
        goto clean;
    }

    status = hashBufferC(&ctxt, buffer, buffer_ln, hash_bytes, hash_bytes_size);

clean:
    cleanHashCtxt(&ctxt);

    return status;
}

NTSTATUS hashBufferC(
    _In_ PHashCtxt ctxt,
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    SIZE_T parts;
    ULONG rest;
    SIZE_T i;
    SIZE_T offset;

    if ( hash_bytes_size < ctxt->HashSize )
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto clean;
    }

    status = createHash(ctxt);
    if ( status != 0 )
    {
        goto clean;
    }

    offset = 0;
    parts = buffer_ln / ULONG_MAX;
    rest = (ULONG)(buffer_ln % ULONG_MAX);

    for ( i = 0; i < parts; i++ )
    {
        status = BCryptHashData(ctxt->Hash, &buffer[offset], (ULONG)ULONG_MAX, 0);
        if ( status != 0 )
        {
            EPrint("BCryptHashData failed! (0x%x)\n", status);
            goto clean;
        }
        offset += ULONG_MAX;
    }
    if ( rest != 0 )
    {
        status = BCryptHashData(ctxt->Hash, &buffer[offset], rest, 0);
        if ( status != 0 )
        {
            EPrint("BCryptHashData failed! (0x%x)\n", status);
            goto clean;
        }
    }

    // close the hash
    status = BCryptFinishHash(ctxt->Hash, hash_bytes, ctxt->HashSize, 0);
    if ( status != 0 )
    {
        EPrint("BCryptFinishHash failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    ;

    return status;
}



//
// SHA256 wrapper
//

NTSTATUS sha256File(_In_ PWCHAR path, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashFile(BCRYPT_SHA256_ALGORITHM, path, hash_bytes, hash_bytes_size);
}

NTSTATUS sha256FileC(_In_ PSha256Ctxt ctxt, _In_ PWCHAR path, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashFileC(ctxt, path, hash_bytes, hash_bytes_size);
}

NTSTATUS sha256Buffer(_In_ PUINT8 buffer, _In_ SIZE_T buffer_ln, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashBuffer(BCRYPT_SHA256_ALGORITHM, buffer, buffer_ln, hash_bytes, hash_bytes_size);
}

NTSTATUS sha256BufferC(_In_ PSha256Ctxt ctxt, _In_ PUINT8 buffer, _In_ SIZE_T buffer_ln, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashBufferC(ctxt, buffer, buffer_ln, hash_bytes, hash_bytes_size);
}

//
// SHA1 wrapper
//

NTSTATUS sha1File(_In_ PWCHAR path, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashFile(BCRYPT_SHA1_ALGORITHM, path, hash_bytes, hash_bytes_size);
}

NTSTATUS sha1FileC(_In_ PSha1Ctxt ctxt, _In_ PWCHAR path, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashFileC(ctxt, path, hash_bytes, hash_bytes_size);
}

NTSTATUS sha1Buffer(_In_ PUINT8 buffer, _In_ SIZE_T buffer_ln, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashBuffer(BCRYPT_SHA1_ALGORITHM, buffer, buffer_ln, hash_bytes, hash_bytes_size);
}

NTSTATUS sha1BufferC(_In_ PSha1Ctxt ctxt, _In_ PUINT8 buffer, _In_ SIZE_T buffer_ln, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashBufferC(ctxt, buffer, buffer_ln, hash_bytes, hash_bytes_size);
}

NTSTATUS md5File(_In_ PWCHAR path, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashFile(BCRYPT_MD5_ALGORITHM, path, hash_bytes, hash_bytes_size);
}

//
// MD5 wrapper
//

NTSTATUS md5FileC(_In_ PMd5Ctxt ctxt, _In_ PWCHAR path, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashFileC(ctxt, path, hash_bytes, hash_bytes_size);
}

NTSTATUS md5Buffer(_In_ PUINT8 buffer, _In_ SIZE_T buffer_ln, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashBuffer(BCRYPT_MD5_ALGORITHM, buffer, buffer_ln, hash_bytes, hash_bytes_size);
}

NTSTATUS md5BufferC(_In_ PMd5Ctxt ctxt, _In_ PUINT8 buffer, _In_ SIZE_T buffer_ln, _Out_ PUINT8 hash_bytes, _In_ UINT16 hash_bytes_size)
{
    return hashBufferC(ctxt, buffer, buffer_ln, hash_bytes, hash_bytes_size);
}



//
// context initialization
// 

NTSTATUS initSha1(_Out_ PSha1Ctxt ctxt)
{
    return initHashCtxt(BCRYPT_SHA1_ALGORITHM, 0, ctxt);
}

NTSTATUS initSha256(_Out_ PSha256Ctxt ctxt)
{
    return initHashCtxt(BCRYPT_SHA256_ALGORITHM, 0, ctxt);
}

NTSTATUS initMd5(_Out_ PMd5Ctxt ctxt)
{
    return initHashCtxt(BCRYPT_MD5_ALGORITHM, 0, ctxt);
}

NTSTATUS initHashCtxt(_In_ PWCHAR AlgId, _In_ ULONG Flags, _Out_ PHashCtxt ctxt)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    RtlZeroMemory(ctxt, sizeof(HashCtxt));

    //open an algorithm handle
    status = BCryptOpenAlgorithmProvider(
        &(ctxt->Alg),
        AlgId,
        NULL,
        Flags);
    if (status != 0)
    {
        EPrint("BCryptOpenAlgorithmProvider failed! (0x%x)\n", status);
        cleanHashCtxt(ctxt);
        return status;
    }

    ctxt->Flags = Flags;

    //calculate the size of the buffer to hold the hash object
    status = BCryptGetProperty(
        ctxt->Alg,
        BCRYPT_OBJECT_LENGTH,
        (PUINT8) &(ctxt->HashObjectSize),
        sizeof(ULONG),
        &(ctxt->DataSize),
        0);
    if (status != 0)
    {
        EPrint("BCryptGetProperty failed! (0x%x)\n", status);
        cleanHashCtxt(ctxt);
        return status;
    }

    // allocate the hash object on the heap
    ctxt->HashObject = (PUINT8)ExAllocatePoolWithTag(PagedPool, ctxt->HashObjectSize, 'hsah');
    if ( NULL == ctxt->HashObject )
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        EPrint("Memory allocation failed! (0x%x)\n", status);
        cleanHashCtxt(ctxt);
        return status;
    }

    // calculate the length of the hash
    status = BCryptGetProperty(
                ctxt->Alg,
                BCRYPT_HASH_LENGTH,
                (PUINT8)&(ctxt->HashSize),
                sizeof(ULONG),
                &(ctxt->DataSize),
                0
            );
    if ( status != 0 )
    {
        EPrint("BCryptGetProperty failed! (0x%x)\n", status);
        cleanHashCtxt(ctxt);
        return status;
    }

    return status;
}

NTSTATUS createHash(_In_ PHashCtxt ctxt)
{
    if ( ctxt->Hash )
    {
        // if hash is already created but not reusable destroy it
        if ( !(ctxt->Flags&BCRYPT_HASH_REUSABLE_FLAG) )
        {
            BCryptDestroyHash(ctxt->Hash);
            ctxt->Hash = NULL;
        }
        else
        {
            // if hash is already created and reusable, just return
            return 0;
        }
    }

    // create new hash object
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    status = BCryptCreateHash(
                ctxt->Alg,
                &(ctxt->Hash),
                ctxt->HashObject,
                ctxt->HashObjectSize,
                NULL,
                0,
                (ctxt->Flags&BCRYPT_HASH_REUSABLE_FLAG)
            );
    if ( status != 0 )
    {
        EPrint("Error (0x%x): BCryptCreateHash\n", status);
        cleanHashCtxt(ctxt);
        return status;
    }
    return status;
}

NTSTATUS cleanSha1(_Inout_ PSha1Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

NTSTATUS cleanSha256(_Inout_ PSha256Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

NTSTATUS cleanMd5(_Inout_ PMd5Ctxt ctxt)
{
    return cleanHashCtxt(ctxt);
}

NTSTATUS cleanHashCtxt(_Inout_ PHashCtxt ctxt)
{
    if (ctxt->Alg)
    {
        BCryptCloseAlgorithmProvider(ctxt->Alg, 0);
        ctxt->Alg = NULL;
    }

    if (ctxt->Hash)
    {
        BCryptDestroyHash(ctxt->Hash);
        ctxt->Hash = NULL;
    }

    if (ctxt->HashObject)
    {
        ExFreePool(ctxt->HashObject);
        ctxt->HashObject = NULL;
    }

    return 0;
}


void hashToString(_In_ const PUINT8 Hash, _In_ UINT16 HashSize, _Out_ char* output, _In_ UINT16 output_size)
{
    UINT16 i = 0;

    for (i = 0; i < HashSize; i++)
    {
        sprintf_s(output + (i * 2), output_size, "%02x", Hash[i]);
    }

    output[output_size-1] = 0;
}

void printHash(_In_ const PUINT8 Hash, _In_ UINT16 HashSize, _In_ const char* prefix, _In_ const char* postfix)
{
    UINT16 i = 0;

    printf("%s", prefix);
    for ( i = 0; i < HashSize; i++ )
    {
        printf("%02x", Hash[i]);
    }
    printf("%s", postfix);
}
