#ifndef CONVERTER_H
#define CONVERTER_H

#include <windows.h>




#define IS_NUM_CHAR(__char__) \
    ( __char__ >= '0' && __char__ <= '9' )

#define IS_LC_HEX_CHAR(__char__) \
    ( __char__ >= 'a' && __char__ <= 'f' )

#define IS_UC_HEX_CHAR(__char__) \
    ( __char__ >= 'A' && __char__ <= 'F' )

#define IN_HEX_RANGE(__char__) \
    ( IS_NUM(__char__) || ( __char__ >= 'a' && __char__ <= 'f' )  || ( __char__ >= 'A' && __char__ <= 'F' ) )

/**
 * Parse plain byte string into byte array
 */
INT parsePlainBytes(
    _In_ const char* Raw, 
    _Inout_ PUINT8* Buffer, 
    _Inout_ PULONG Size, 
    _In_ ULONG MaxBytes
)
{
    ULONG i, j;
    SIZE_T raw_size = strlen(Raw);
    PUINT8 p = NULL;
    BOOL malloced = FALSE;
    ULONG buffer_size;
    int s = 0;

    UINT8 m1, m2;

    if ( raw_size > MaxBytes * 2ULL )
    {
        EPrint("Data too big!\n");
        return ERROR_BUFFER_OVERFLOW;
    }

    if ( raw_size == 0 )
    {
        EPrint("Buffer is empty!\n");
        return ERROR_INVALID_PARAMETER;
    }
    if ( raw_size % 2 != 0 )
    {
        EPrint("Buffer data is not byte aligned!\n");
        return ERROR_INVALID_PARAMETER;
    }
    
    buffer_size = (ULONG) (raw_size / 2);

    if ( *Size && *Buffer && buffer_size > *Size )
    {
        EPrint("Provided buffer is too small: 0x%x < 0x%x!\n", *Size, buffer_size);
        return ERROR_INVALID_PARAMETER;
    }

    if ( *Buffer == NULL )
    {
        p = (PUINT8) malloc(buffer_size);
        if ( p == NULL )
        {
            EPrint("No memory!\n");
            return GetLastError();
        }
        malloced = TRUE;
    }
    else
    {
        p = *Buffer;
    }

    for ( i = 0, j = 0; i < raw_size; i += 2, j++ )
    {
        if ( IS_NUM_CHAR(Raw[i]) )
            m1 = 0x30;
        else if ( IS_UC_HEX_CHAR(Raw[i]) )
            m1 = 0x37;
        else if ( IS_LC_HEX_CHAR(Raw[i]) )
            m1 = 0x57;
        else
        {
            s = ERROR_INVALID_PARAMETER;
            EPrint("Byte string not in hex range!\n");
            break;
        }
        
        if ( IS_NUM_CHAR(Raw[i+1]) )
            m2 = 0x30;
        else if ( IS_UC_HEX_CHAR(Raw[i+1]) )
            m2 = 0x37;
        else if ( IS_LC_HEX_CHAR(Raw[i+1]) )
            m2 = 0x57;
        else
        {
            s = ERROR_INVALID_PARAMETER;
            EPrint("Byte string not in hex range!\n");
            break;
        }

        p[j] = ((Raw[i] - m1)<<4) | ((Raw[i+1] - m2) & 0x0F);
    }
    
    if ( s != 0 )
    {
        if ( malloced && p )
            free(p);
    }
    else
    {
        *Size = buffer_size;
        *Buffer = p;
    }

    return s;
}

#endif
