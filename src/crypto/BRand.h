#pragma once


#include <bcrypt.h>


NTSTATUS generateRand(
    PUINT8 Buffer,
    ULONG BufferSize
)
{
    int s;
    RtlZeroMemory(Buffer, BufferSize);
    s = BCryptGenRandom(
        NULL,
        Buffer,
        BufferSize,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    return s;
}
