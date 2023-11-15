#pragma once

#include <windows.h>

#include "../inc/nt.h"

#define CRYPT_STRING_BASE64HEADER           0x00000000
#define CRYPT_STRING_BASE64                 0x00000001
#define CRYPT_STRING_BINARY                 0x00000002
#define CRYPT_STRING_BASE64REQUESTHEADER    0x00000003
#define CRYPT_STRING_HEX                    0x00000004
#define CRYPT_STRING_HEXASCII               0x00000005
#define CRYPT_STRING_BASE64_ANY             0x00000006
#define CRYPT_STRING_ANY                    0x00000007
#define CRYPT_STRING_HEX_ANY                0x00000008
#define CRYPT_STRING_BASE64X509CRLHEADER    0x00000009
#define CRYPT_STRING_HEXADDR                0x0000000a
#define CRYPT_STRING_HEXASCIIADDR           0x0000000b
#define CRYPT_STRING_HEXRAW                 0x0000000c
#define CRYPT_STRING_BASE64URI              0x0000000d

#define CRYPT_STRING_ENCODEMASK             0x000000ff
#define CRYPT_STRING_RESERVED100            0x00000100
#define CRYPT_STRING_RESERVED200            0x00000200

#define CRYPT_STRING_PERCENTESCAPE          0x08000000	// base64 formats only
#define CRYPT_STRING_HASHDATA               0x10000000
#define CRYPT_STRING_STRICT                 0x20000000
#define CRYPT_STRING_NOCRLF                 0x40000000
#define CRYPT_STRING_NOCR                   0x80000000


NTSTATUS B64_encodeFile(
    _In_ PWCHAR Path, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize,
    _In_ ULONG Flags
);

NTSTATUS B64_decodeFile(
    _In_ PWCHAR Path, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize
);

NTSTATUS B64_encode(
    _In_ PUINT8 Input, 
    _In_ ULONG InputSize, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize,
    _In_ ULONG Flags
);

NTSTATUS B64_decode(
    _In_ PUINT8 Input, 
    _In_ ULONG InputSize, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize
);
