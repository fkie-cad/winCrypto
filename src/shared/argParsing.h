#pragma once

INT fillNtPath(_In_ PCHAR Path, _Out_ PWCHAR* NtPath)
{
    INT s;

    ULONG pathCch = (ULONG)strlen(Path);
    ULONG ntPathCb = pathCch * 2;
    PWCHAR pathW = NULL;

    *NtPath = NULL;

    pathW = malloc(ntPathCb + 2);
    if ( !pathW )
    {
        s = GetLastError();
        goto clean;
    }
    s = StringCchPrintfW(pathW, pathCch+1, L"%hs", Path);
    if ( s != S_OK )
        goto clean;

    ntPathCb = RtlGetFullPathName_U(pathW, 0, NULL, NULL);
    ntPathCb += 8; // nt prefix w (8)
    *NtPath = (PWCHAR)malloc(ntPathCb); // L'0' (2)
    if ( *NtPath == NULL )
    {
        s = ERROR_NOT_ENOUGH_MEMORY;
        EPrint("Not enough memory for path\n");
        goto clean;
    }

    s = ntGetFullPathName(pathW, ntPathCb, *NtPath, NULL);
    if ( s == 0 || s >= (INT)ntPathCb )
    {
        s = -1;
        EPrint("ntGetFullPathName failed! (0x%x)\n", s);
        goto clean;
    }
    s = 0;

clean:
    if ( pathW )
        free(pathW);

    return s;
}
