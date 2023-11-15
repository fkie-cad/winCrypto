#include "AESCNG.h"

#ifdef RING3
#include <stdio.h>
#include <stdlib.h>
#include "../inc/nt.h"
#endif

#include "../shared/print.h"

#ifdef RING3
#define ExAllocatePoolWithTag(_pt_, _n_, _t_) malloc(_n_)
#define ExFreePool(_p_) free(_p_)
#endif



NTSTATUS AES_init(
    PAES_CTXT Ctxt
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG size;
    
    RtlZeroMemory(Ctxt, sizeof(AES_CTXT));

    // Open provider.
    status = BCryptOpenAlgorithmProvider(
        &Ctxt->Alg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptOpenAlgorithmProvider failed! (0x%x)\n", status);
        return status;
    }

    // Calculate the block length
    status = BCryptGetProperty(
        Ctxt->Alg, 
        BCRYPT_BLOCK_LENGTH, 
        (PUCHAR)&Ctxt->BlockSize, 
        sizeof(Ctxt->BlockSize), 
        &size, 
        0
    );
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Getting block length failed! (0x%x)\n", status);
        Ctxt->BlockSize = 0;
        return status;
    }

    // Set chain mode CBC
    status = BCryptSetProperty(
        Ctxt->Alg, 
        BCRYPT_CHAINING_MODE, 
        (PUINT8)BCRYPT_CHAIN_MODE_CBC, 
        sizeof(BCRYPT_CHAIN_MODE_CBC), 
        0
    );
    if ( !NT_SUCCESS(status) )
    {
        EPrint("Setting chain mode failed! (0x%x)\n", status);
        return status;
    }

    return status;
}

NTSTATUS AES_generateKey(
    PAES_CTXT Ctxt,
    PUCHAR Secret,
    ULONG SecretSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG data_ln;

    // get needed length of key block
    status = BCryptGetProperty(
        Ctxt->Alg,
        BCRYPT_OBJECT_LENGTH, 
        (PUINT8)&Ctxt->KeyObjSize, 
        sizeof(ULONG), 
        &data_ln, 
        0
    );
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptGetProperty failed! (0x%x)\n", status);
        goto clean;
    }

    // Allocate the key object on the heap.
    Ctxt->KeyObj = (PUCHAR) ExAllocatePoolWithTag(PagedPool, Ctxt->KeyObjSize, 'yrck');
    if( Ctxt->KeyObj == NULL )
    {
        status = STATUS_NO_MEMORY;
        EPrint("Allocating memory for key object failed! (0x%x)\n", status);
        goto clean;
    }

    // generate key 
    status = BCryptGenerateSymmetricKey(
        Ctxt->Alg,
        &Ctxt->Key,
        Ctxt->KeyObj,
        Ctxt->KeyObjSize,
        Secret,
        SecretSize,
        0
    );
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptGenerateSymmetricKey failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    ;
    return status;
}

BOOLEAN buffersAreOverlapping(
    PVOID Buffer1, 
    ULONG Buffer1Size, 
    PVOID Buffer2, 
    ULONG Buffer2Size, 
    BOOLEAN mayBeEqual
)
{
    SIZE_T Address1 = (SIZE_T)Buffer1;
    SIZE_T Address2 = (SIZE_T)Buffer2;

    if ( Buffer1 == NULL || Buffer2 == NULL )
        return FALSE;
    if ( Address1 == Address2 )
        return !mayBeEqual;

    if ( Address1 < Address2 )
    {
        return !(Address1 + Buffer1Size <= Address2);
        //return Address1 + Buffer1Size > Address2;
    }
    else
    {
        return !(Address2 + Buffer2Size <= Address1);
        //return Address2 + Buffer2Size > Address1;
    }
}

NTSTATUS AES_encrypt(
    PAES_CTXT Ctxt,
    PUCHAR Plain,
    ULONG PlainSize,
    PUCHAR* Encrypted,
    PULONG EncryptedSize,
    PUCHAR Iv,
    ULONG IvSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR ivt[AES_STD_BLOCK_SIZE];
    ULONG size;
    
    // check if buffers are overlapping
    if ( buffersAreOverlapping(Plain, PlainSize, *Encrypted, *EncryptedSize, TRUE) )
    {
        status = STATUS_BUFFER_OVERFLOW; // is there better status??
        EPrint("Buffers are overlapping! (0x%x)\n", status);
        goto clean;
    }


    // copy iv, because it will be consumed during encryption
    if ( IvSize != AES_STD_BLOCK_SIZE )
    {
        status = STATUS_UNSUCCESSFUL;
        EPrint("Unknown size of IV! (0x%x)\n", status);
        goto clean;
    }

    RtlCopyMemory(ivt, Iv, IvSize);
    
    // Get the output buffer size.
    status = BCryptEncrypt(
        Ctxt->Key, 
        Plain, 
        PlainSize,
        NULL,
        ivt,
        Ctxt->BlockSize,
        NULL, 
        0, 
        &size, 
        BCRYPT_BLOCK_PADDING
    );
    if( !NT_SUCCESS(status) )
    {
        EPrint("BCryptEncrypt get size failed! (0x%x)\n", status);
        goto clean;
    }
    
    if ( *Encrypted == NULL )
    {
        *Encrypted = (PUCHAR) ExAllocatePoolWithTag(PagedPool, size, 'yrck');
        if ( *Encrypted == NULL )
        {
            status = STATUS_NO_MEMORY;
            EPrint("Allocating encrypted buffer failed! (0x%x)\n", status);
            goto clean;
        }
    }
    else
    {
        if ( size > *EncryptedSize )
        {
            status = STATUS_BUFFER_TOO_SMALL;
            EPrint("Provided encryption buffer[0x%x] is too small! 0x%x needed! (0x%x)\n", *EncryptedSize, size, status);
            goto clean;
        }
    }
    *EncryptedSize = size;
    
    if ( Plain != *Encrypted )
        RtlZeroMemory(*Encrypted, *EncryptedSize);
    
    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    status = BCryptEncrypt(
        Ctxt->Key, 
        Plain, 
        PlainSize,
        NULL,
        ivt,
        Ctxt->BlockSize, 
        *Encrypted, 
        *EncryptedSize, 
        &size, 
        BCRYPT_BLOCK_PADDING
    );
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptEncrypt failed! (0x%x)\n", status);
        goto clean;
    }

clean:
    ;

    return status;
}

NTSTATUS AES_decrypt(
    PAES_CTXT Ctxt,
    PUCHAR Encrypted,
    ULONG EncryptedSize,
    PUCHAR* Plain,
    PULONG PlainSize,
    PUCHAR Iv,
    ULONG IvSize
)
{
    NTSTATUS status = STATUS_SUCCESS;
    //PUCHAR ivt = NULL;
    UCHAR ivt[AES_STD_BLOCK_SIZE];
    ULONG size = EncryptedSize;
    
    // check if buffers are overlapping
    if ( buffersAreOverlapping(Encrypted, EncryptedSize, *Plain, *PlainSize, TRUE) )
    {
        status = STATUS_BUFFER_OVERFLOW; // is there better status??
        EPrint("Buffers are overlapping! (0x%x)\n", status);
        goto clean;
    }
    
    // copy iv, because it will be consumed during encryption
    if ( IvSize != AES_STD_BLOCK_SIZE )
    {
        status = STATUS_UNSUCCESSFUL;
        EPrint("Unknown size of IV! (0x%x)\n", status);
        goto clean;
    }
    RtlCopyMemory(ivt, Iv, IvSize);
    
    // Get the output buffer size.
    // not needed, because the returned size will be EncryptedSize
    
    if ( *Plain == NULL )
    {
        *Plain = (PUCHAR) ExAllocatePoolWithTag(PagedPool, size, 'yrck');
        if ( *Plain == NULL )
        {
            status = STATUS_NO_MEMORY;
            EPrint("Allocating plain buffer failed! (0x%x)\n", status);
            goto clean;
        }
    }
    else
    {
        if ( size > *PlainSize )
        {
            status = STATUS_BUFFER_TOO_SMALL;
            EPrint("Provided plain buffer[0x%x] is too small! 0x%x needed! (0x%x)\n", *PlainSize, size, status);
            goto clean;
        }
    }
    
    if ( Encrypted != *Plain )
        RtlZeroMemory(*Plain, size);
    
    status = BCryptDecrypt(
        Ctxt->Key,
        Encrypted, 
        EncryptedSize, 
        NULL,
        ivt,
        Ctxt->BlockSize,
        *Plain, 
        size, 
        &size, 
        BCRYPT_BLOCK_PADDING
    );
    if ( !NT_SUCCESS(status) )
    {
        EPrint("BCryptDecrypt failed! (0x%x)\n", status);
        goto clean;
    }
    *PlainSize = size;

clean:
    ;

    return status;
}

NTSTATUS AES_clean(
    PAES_CTXT Ctxt
)
{
    if ( Ctxt->Alg )
    {
        BCryptCloseAlgorithmProvider(Ctxt->Alg, 0);
        Ctxt->Alg = NULL;
    }

    AES_deleteKey(Ctxt);

    RtlZeroMemory(Ctxt, sizeof(*Ctxt));

    return STATUS_SUCCESS;
}

NTSTATUS AES_deleteKey(
    PAES_CTXT Ctxt
)
{
    if ( Ctxt->Key )
    {
        BCryptDestroyKey(Ctxt->Key);
        Ctxt->Key = NULL;
    }

    if ( Ctxt->KeyObj )
    {
        RtlZeroMemory(Ctxt->KeyObj, Ctxt->KeyObjSize);
        ExFreePool(Ctxt->KeyObj);
        Ctxt->KeyObj = NULL;
        Ctxt->KeyObjSize = 0;
    }

    return 0;
}
