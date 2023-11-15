#pragma once

#include <windows.h>
#include <bcrypt.h>

#include "../inc/nt.h"


#define MD5_BYTES_LN (0x10)
#define MD5_STRING_LN (0x20)
#define MD5_STRING_BUFFER_LN (0x21)
 
#define SHA1_BYTES_LN (0x14)
#define SHA1_STRING_LN (0x28)
#define SHA1_STRING_BUFFER_LN (0x29)

#define SHA256_BYTES_LN (0x20)
#define SHA256_STRING_LN (0x40)
#define SHA256_STRING_BUFFER_LN (0x41)


typedef struct HashCtxt {
    BCRYPT_ALG_HANDLE Alg;
    BCRYPT_HASH_HANDLE Hash;
    NTSTATUS Status;
    ULONG DataSize;
    ULONG HashSize;
    ULONG HashObjectSize;
    PUINT8 HashObject;
} 
HashCtxt, *PHashCtxt,
Md5Ctxt, *PMd5Ctxt,
Sha1Ctxt, *PSha1Ctxt,
Sha256Ctxt, *PSha256Ctxt;



#ifdef __cplusplus
extern "C"{
#endif


NTSTATUS initSha1(
    _Out_ PSha1Ctxt Ctxt
);

NTSTATUS initSha256(
    _Out_ PSha256Ctxt Ctxt
);

NTSTATUS initMd5(
    _Out_ PMd5Ctxt Ctxt
);

NTSTATUS initHashCtxt(
    _Out_ PHashCtxt Ctxt, 
    _In_ PWCHAR AlgId
);

NTSTATUS cleanSha1(
    _Inout_ PSha1Ctxt Ctxt);

NTSTATUS cleanSha256(
    _Inout_ PSha256Ctxt Ctxt
);

NTSTATUS cleanMd5(
    _Inout_ PMd5Ctxt Ctxt
);

NTSTATUS cleanHashCtxt(
    _Inout_ PHashCtxt Ctxt
);


/**
 * Create sha256 Hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   Path char* the input file path
 * @param   HashBytes PUINT8 The input Hash bytes
 * @param   HashSize ULONG Size of the HashBytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256File(
    _In_ PWCHAR Path, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
);


/**
 * Create sha256 Hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   Path char* the input file path
 * @param   HashBytes PUINT8 The input Hash bytes
 * @param   HashSize ULONG Size of the HashBytes.
 * @return  Ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256FileC(
    _In_ PWCHAR Path, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PSha256Ctxt Ctxt
);

/**
 * Create sha256 Hash of a given Buffer.
 *
 * @param   Buffer UINT8* the input Buffer
 * @param   BufferSize UINT32 size of Buffer
 * @param   PUINT8 HashBytes, 
 * @param   HashBytesSize ULONG Size of the HashBytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256Buffer(
    _In_ UINT8* Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
);

/**
 * Create sha256 Hash of a given Buffer.
 *
 * @param   Buffer UINT8* the input Buffer
 * @param   BufferSize UINT32 size of Buffer
 * @param   PUINT8 HashBytes, 
 * @param   HashBytesSize ULONG Size of the HashBytes.
 * @return  Ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256BufferC(
    _In_ UINT8* Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PSha256Ctxt Ctxt
);

/**
 * Create sha1 Hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   Path char* the input file path
 * @param   HashBytes PUINT8 The input Hash bytes
 * @param   HashSize ULONG Size of the HashBytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1File(
    _In_ PWCHAR Path, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
);


/**
 * Create sha1 Hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   Path char* the input file path
 * @param   HashBytes PUINT8 The input Hash bytes
 * @param   HashSize ULONG Size of the HashBytes.
 * @return  Ctxt PSha1Ctxt initialized Sha1Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1FileC(
    _In_ PWCHAR Path, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PSha1Ctxt Ctxt
);

/**
 * Create sha1 Hash of a given Buffer.
 *
 * @param   Buffer UINT8* the input Buffer
 * @param   BufferSize UINT32 size of Buffer
 * @param   PUINT8 HashBytes, 
 * @param   HashBytesSize ULONG Size of the HashBytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1Buffer(
    _In_ UINT8* Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
);

/**
 * Create sha1 Hash of a given Buffer.
 *
 * @param   Buffer UINT8* the input Buffer
 * @param   BufferSize UINT32 size of Buffer
 * @param   PUINT8 HashBytes, 
 * @param   HashBytesSize ULONG Size of the HashBytes.
 * @return  Ctxt PSha1Ctxt initialized Sha1Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1BufferC(
    _In_ UINT8* Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PSha1Ctxt Ctxt
);


/**
 * Create md5 Hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   Path char* the input file path
 * @param   HashBytes PUINT8 The input Hash bytes
 * @param   HashSize ULONG Size of the HashBytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS md5File(
    _In_ PWCHAR Path, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
);


/**
 * Create md5 Hash of a given file.
 * Using a FILE* to open the file.
 *
 * @param   Path char* the input file path
 * @param   HashBytes PUINT8 The input Hash bytes
 * @param   HashSize ULONG Size of the HashBytes.
 * @return  Ctxt PMd5Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS md5FileC(
    _In_ PWCHAR Path, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PMd5Ctxt Ctxt
);

/**
 * Create md5 Hash of a given Buffer.
 *
 * @param   Buffer UINT8* the input Buffer
 * @param   BufferSize UINT32 size of Buffer
 * @param   PUINT8 HashBytes, 
 * @param   HashBytesSize ULONG Size of the HashBytes.
 * @return  NTSTATUS the success state
 */
NTSTATUS md5Buffer(
    _In_ UINT8* Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize
);

/**
 * Create md5 Hash of a given Buffer.
 *
 * @param   Buffer UINT8* the input Buffer
 * @param   BufferSize UINT32 size of Buffer
 * @param   PUINT8 HashBytes, 
 * @param   HashBytesSize ULONG Size of the HashBytes.
 * @return  Ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS md5BufferC(
    _In_ UINT8* Buffer, 
    _In_ SIZE_T BufferSize, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PMd5Ctxt Ctxt
);


/**
 * Convert Hash bytes to ascii string.
 *
 * @param   Hash PUINT8 The input Hash bytes
 * @param   HashSize UINT16 Size of the HashBytes.
 * @param   Output char* The Output Hash string
 * @param   OutputSize UINT16 The outout Buffer size. Should be at least HashSize*2 + 1.
 */
void hashToString(
    _In_ const PUINT8 Hash, 
    _In_ UINT16 HashSize, 
    _Out_ char* Output, 
    _In_ UINT16 OutputSize
);

/**
 * Print the Hash to stdout.
 *
 * @param   Hash PUINT8 The input Hash bytes
 * @param   HashSize UINT16 Size of the HashBytes.
 * @param   Prefix char* A Prefix.
 * @param   Postfix char* A Postfix.
 */
void printHash(
    _In_ const PUINT8 Hash, 
    _In_ UINT16 HashSize, 
    _In_ const char* Prefix, 
    _In_ const char* Postfix
);

#ifdef __cplusplus
}
#endif
