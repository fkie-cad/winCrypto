#ifndef SHARED_FILES_W_H
#define SHARED_FILES_W_H

#include <windows.h>

#include "../inc/nt.h"



#define PATH_SEPARATOR 0x5C

#define NT_FILE_READ_ACCESS     (FILE_GENERIC_READ | SYNCHRONIZE)
#define NT_FILE_WRITE_ACCESS    (FILE_GENERIC_WRITE | SYNCHRONIZE)

#define NT_PATH_PREFIX_W (0x005c003f003f005c)

typedef void (*FileCallback)(WCHAR*);
//typedef bool (*Condition)(WCHAR*);



/**
* Find files in directory with specified file_type and call back on each file.
*
* @param    Path WCHAR* the directory to search.
* @param    Cb FileCallback the callback(WCHAR*) called on each found file.
* @param    Types char** A white list of file types to search for. Not implemented yet.
* @param    Recursive BOOL Do a "recursive" search including all subdirectories.
*/
BOOL actOnFilesInDir(
    _In_ const WCHAR* Path, 
    _In_ FileCallback Cb, 
    _In_opt_ const char** Types, 
    _In_ BOOL Recursive
);

ULONG ntGetFullPathName(
    _In_ PWCHAR FileName,
    _In_ ULONG BufferLength,
    _Out_writes_bytes_(BufferLength) PWSTR Buffer,
    _Out_opt_ PWSTR *FilePart
);

BOOLEAN ntFileExists(
    _In_ WCHAR* Path
);

BOOLEAN ntDirExists(
    _In_ WCHAR* Path
);

BOOLEAN ntPathExists(
    _In_ WCHAR* Path, 
    _In_ BOOLEAN isDir
);

NTSTATUS ntOpenFile(
    _In_ PWCHAR Path, 
    _Out_ PHANDLE Handle, 
    _In_ ULONG OpenMode, 
    _In_ ULONG CreateDisposion
);

NTSTATUS ntGetFileSize(
    _In_ HANDLE Handle,
    _Out_ PUINT64 Size
);

NTSTATUS ntGetFileBytes(
    _In_ PWCHAR Path, 
    _Inout_ PUINT8* Output, 
    _Inout_ PULONG OutputSize
);

#endif
