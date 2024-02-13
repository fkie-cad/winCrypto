#pragma once


#include <windows.h>

#include "crypto/HasherCNG.h"


#define BUFFER_SIZE (0x1000)



INT hashDir(
    _In_ WCHAR* Path,
    _In_ ULONG Flags
);

VOID lPrintHash(
    _In_ PUINT8 Bytes, 
    _In_ ULONG Size, 
    _In_ WCHAR* File,
    _In_ PWCHAR Type
);

// in HasherCNG.c
NTSTATUS hashFileC(
    _In_ PWCHAR Path, 
    _Out_ PUINT8 HashBytes, 
    _In_ UINT16 HashBytesSize, 
    _In_ PHashCtxt Ctxt
);
