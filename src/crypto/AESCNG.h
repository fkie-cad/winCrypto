#pragma once

#ifdef RING3
#include <windows.h>
#endif
#include <bcrypt.h>


#define AES_STD_BLOCK_SIZE (0x10)
#define AES_IV_SIZE AES_STD_BLOCK_SIZE



#ifdef __cplusplus
extern "C"{
#endif

typedef struct _AES_CTXT {
    BCRYPT_ALG_HANDLE Alg;
    BCRYPT_KEY_HANDLE Key;
    PUCHAR KeyObj;
    ULONG KeyObjSize;
    ULONG BlockSize;
} AES_CTXT, * PAES_CTXT;

/**
 * Open AES provider, get block size, set cipher mode.
 * Remember to clean.
 */
NTSTATUS AES_init(
    PAES_CTXT Ctxt
);

/**
 * Generate AES key with given secret.
 * Remember to destroy.
 */
NTSTATUS AES_generateKey(
    PAES_CTXT Ctxt,
    PUCHAR Secret,
    ULONG SecretSize
);

/**
 * Encrypt buffer.
 * Allocates enrypted buffer if *encrypted==NULL. Be sure to free it afterwards.
 * plain = *enrypted may be equal, if not, they may not overlap!!
 */
NTSTATUS AES_encrypt(
    PAES_CTXT Ctxt,
    PUCHAR Plain,
    ULONG PlainSize,
    PUCHAR* Enrypted,
    PULONG EnryptedSize,
    PUCHAR Iv,
    ULONG IvSize
);

/**
 * Decrypt buffer.
 * The required size of the plain buffer will be the size of the encrypted buffer, not the original size.
 * Allocates plain buffer if *plain==NULL. Be sure to free it afterwards.
 * enrypted = *plain may be equal, if not, they may not overlap!!
 */
NTSTATUS AES_decrypt(
    PAES_CTXT Ctxt,
    PUCHAR encrypted,
    ULONG encrypted_ln,
    PUCHAR* Plain,
    PULONG PlainSize,
    PUCHAR Iv,
    ULONG IvSize
);

/**
 * Clean up.
 * Close provider, destroy key, free key buffer.
 */
NTSTATUS AES_clean(
    PAES_CTXT Ctxt
);

/**
 * Clean up.
 * Destroy key, free key buffer.
 */
NTSTATUS AES_deleteKey(
    PAES_CTXT Ctxt
);

#ifdef __cplusplus
}
#endif
