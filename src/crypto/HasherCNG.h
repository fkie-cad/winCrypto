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

#define SHA384_BYTES_LN (0x30)
#define SHA384_STRING_LN (0x60)
#define SHA384_STRING_BUFFER_LN (0x61)

#define SHA512_BYTES_LN (0x40)
#define SHA512_STRING_LN (0x80)
#define SHA512_STRING_BUFFER_LN (0x81)



#pragma pack(1)
typedef struct HashCtxt {
    BCRYPT_ALG_HANDLE Alg; // 0
    BCRYPT_HASH_HANDLE Hash; // 8
    NTSTATUS Status; // 10
    ULONG DataSize; // 14
    ULONG HashSize; // 18
    ULONG HashObjectSize; // 1C
    PUINT8 HashObject; // 20
    ULONG Flags; // 28
    ULONG Padding; // 2C
} // 30
HashCtxt, *PHashCtxt,
Md5Ctxt, *PMd5Ctxt,
Sha1Ctxt, *PSha1Ctxt,
Sha256Ctxt, *PSha256Ctxt;
#pragma pack()



#ifdef __cplusplus
extern "C"{
#endif

/**
 * Init SHA1 context object.
 * 
 * Open algorithm provider.
 * Get hash, object and data size.
 * Allocate hash object.
 * 
 * @param ctxt PSha256Ctxt Context object to be filled.
 */
NTSTATUS initSha1(
    _Out_ PSha1Ctxt ctxt
);

/**
 * Init SHA256 context object.
 * 
 * Open algorithm provider.
 * Get hash, object and data size.
 * Allocate hash object.
 * 
 * @param ctxt PSha256Ctxt Context object to be filled.
 */
NTSTATUS initSha256(
    _Out_ PSha256Ctxt ctxt
);

/**
 * Init MD5 context object.
 * 
 * Open algorithm provider.
 * Get hash, object and data size.
 * Allocate hash object.
 * 
 * @param ctxt PSha256Ctxt Context object to be filled.
 */
NTSTATUS initMd5(
    _Out_ PMd5Ctxt ctxt
);

/**
 * Init hash context object.
 * 
 * Open algorithm provider.
 * Get hash, object and data size.
 * Allocate hash object.
 * 
 * @param AlgId PWCHAR Hash algorithm id.
 * @param Flags ULONG Provider flags like: BCRYPT_PROV_DISPATCH, BCRYPT_HASH_REUSABLE_FLAG.
 * @param ctxt PSha256Ctxt Context object to be filled.
 */
NTSTATUS initHashCtxt(
    _In_ PWCHAR AlgId, 
    _In_ ULONG Flags, 
    _Out_ PHashCtxt ctxt
);

/**
 * Clean SHA1 hash context object.
 * 
 * Close algorithm provider.
 * Destroy hash object.
 * 
 * @param ctxt PSha256Ctxt Context object to be used.
 */
NTSTATUS cleanSha1(
    _Inout_ PSha1Ctxt ctxt);

/**
 * Clean SHA256 hash context object.
 * 
 * Close algorithm provider.
 * Destroy hash object.
 * 
 * @param ctxt PSha256Ctxt Context object to be used.
 */
NTSTATUS cleanSha256(
    _Inout_ PSha256Ctxt ctxt
);

/**
 * Clean MD5 hash context object.
 * 
 * Close algorithm provider.
 * Destroy hash object.
 * 
 * @param ctxt PSha256Ctxt Context object to be used.
 */
NTSTATUS cleanMd5(
    _Inout_ PMd5Ctxt ctxt
);

/**
 * Clean hash context object.
 * 
 * Close algorithm provider.
 * Destroy hash object.
 * 
 * @param ctxt PSha256Ctxt Context object to be used.
 */
NTSTATUS cleanHashCtxt(
    _Inout_ PHashCtxt ctxt
);


/**
 * Create hash of a given file.
 *
 * @param   AlgId PWCHAR Hash algorithm id.
 * @param   path PWCHAR The input file path
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  NTSTATUS the success state
 */
NTSTATUS hashFile(
    _In_ PWCHAR AlgId,
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
);

/**
 * Create hash of a given file.
 *
 * @param   path PWCHAR the input file path
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @param   ctxt PHashCtxt The initialized hash context object.
 * @return  NTSTATUS the success state
 */
NTSTATUS hashFileC(
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size, 
    _In_ PHashCtxt ctxt
);

/**
 * Create hash of a given buffer.
 *
 * @param   AlgId PWCHAR Hash algorithm id.
 * @param   buffer UINT8* the input buffer
 * @param   buffer_ln SIZE_T size of buffer
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  NTSTATUS the success state
 */
NTSTATUS hashBuffer(
    _In_ PWCHAR AlgId, 
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
);

/**
 * Create hash of a given buffer.
 *
 * @param   buffer UINT8* the input buffer
 * @param   buffer_ln SIZE_T size of buffer
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  ctxt PHashCtxt initialized HashCtxt
 * @return  NTSTATUS the success state
 */
NTSTATUS hashBufferC(
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size, 
    _In_ PHashCtxt ctxt
);

/**
 * Create sha256 hash of a given file.
 *
 * @param   path PWCHAR the input file path
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256File(
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
);


/**
 * Create sha256 hash of a given file.
 *
 * @param   path PWCHAR the input file path
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256FileC(
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size, 
    _In_ PSha256Ctxt ctxt
);

/**
 * Create sha256 hash of a given buffer.
 *
 * @param   buffer UINT8* the input buffer
 * @param   buffer_ln SIZE_T size of buffer
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256Buffer(
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
);

/**
 * Create sha256 hash of a given buffer.
 *
 * @param   buffer UINT8* the input buffer
 * @param   buffer_ln SIZE_T size of buffer
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha256BufferC(
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size, 
    _In_ PSha256Ctxt ctxt
);

/**
 * Create sha1 hash of a given file.
 *
 * @param   path PWCHAR the input file path
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1File(
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
);


/**
 * Create sha1 hash of a given file.
 *
 * @param   path PWCHAR the input file path
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  ctxt PSha1Ctxt initialized Sha1Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1FileC(
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size, 
    _In_ PSha1Ctxt ctxt
);

/**
 * Create sha1 hash of a given buffer.
 *
 * @param   buffer UINT8* the input buffer
 * @param   buffer_ln SIZE_T size of buffer
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1Buffer(
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
);

/**
 * Create sha1 hash of a given buffer.
 *
 * @param   buffer UINT8* the input buffer
 * @param   buffer_ln SIZE_T size of buffer
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  ctxt PSha1Ctxt initialized Sha1Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS sha1BufferC(
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size, 
    _In_ PSha1Ctxt ctxt
);


/**
 * Create md5 hash of a given file.
 *
 * @param   path PWCHAR the input file path
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  NTSTATUS the success state
 */
NTSTATUS md5File(
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
);


/**
 * Create md5 hash of a given file.
 *
 * @param   path PWCHAR the input file path
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  ctxt PMd5Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS md5FileC(
    _In_ PWCHAR path, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size, 
    _In_ PMd5Ctxt ctxt
);

/**
 * Create md5 hash of a given buffer.
 *
 * @param   buffer UINT8* the input buffer
 * @param   buffer_ln SIZE_T size of buffer
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  NTSTATUS the success state
 */
NTSTATUS md5Buffer(
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size
);

/**
 * Create md5 hash of a given buffer.
 *
 * @param   buffer UINT8* the input buffer
 * @param   buffer_ln SIZE_T size of buffer
 * @param   hash_bytes PUINT8 The hash bytes buffer
 * @param   hash_bytes_size UINT16 Size of the hash_bytes buffer.
 * @return  ctxt PSha256Ctxt initialized Sha256Ctxt
 * @return  NTSTATUS the success state
 */
NTSTATUS md5BufferC(
    _In_ PUINT8 buffer, 
    _In_ SIZE_T buffer_ln, 
    _Out_ PUINT8 hash_bytes, 
    _In_ UINT16 hash_bytes_size, 
    _In_ PMd5Ctxt ctxt
);


/**
 * Convert hash bytes to ascii string.
 *
 * @param   hash PUINT8 The input hash bytes
 * @param   hash_size UINT16 Size of the hash_bytes.
 * @param   output char* The output hash string buffer.
 * @param   output_size UINT16 The output buffer size. Should be at least hash_size*2 + 1.
 */
void hashToString(
    _In_ const PUINT8 Hash, 
    _In_ UINT16 HashSize, 
    _Out_ char* output, 
    _In_ UINT16 output_size
);

/**
 * Print the hash to stdout.
 *
 * @param   hash PUINT8 The input hash bytes
 * @param   hash_size UINT16 Size of the hash_bytes.
 * @param   prefix char* A Prefix.
 * @param   postfix char* A Postfix.
 */
void printHash(
    _In_ const PUINT8 Hash, 
    _In_ UINT16 HashSize, 
    _In_ const char* prefix, 
    _In_ const char* postfix
);

#ifdef __cplusplus
}
#endif
