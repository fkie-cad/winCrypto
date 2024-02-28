#pragma once


#ifdef DEBUG_PRINT
#define DPrint(...) \
                printf(__VA_ARGS__);
#define DPrintW(...) \
                wprintf(__VA_ARGS__);
#define FPrint() \
                printf("[>] %s()\n", __FUNCTION__);
#define SPrint(_c_) \
{ \
                printf("[s] "); \
                switch ( _c_ ) { \
                    case STATUS_SUCCESS: printf("STATUS_SUCCESS"); break; \
                    case STATUS_ACCESS_DENIED: printf("STATUS_ACCESS_DENIED"); break; \
                    case STATUS_NO_SUCH_DEVICE: printf("STATUS_NO_SUCH_DEVICE"); break; \
                    case STATUS_NOT_SUPPORTED: printf("STATUS_NOT_SUPPORTED"); break; \
                    case STATUS_ACCESS_VIOLATION: printf("STATUS_ACCESS_VIOLATION"); break; \
                    case STATUS_CONFLICTING_ADDRESSES: printf("STATUS_CONFLICTING_ADDRESSES"); break; \
                    case STATUS_OBJECT_NAME_INVALID: printf("STATUS_OBJECT_NAME_INVALID"); break; \
                    case STATUS_OBJECT_NAME_NOT_FOUND: printf("STATUS_OBJECT_NAME_NOT_FOUND"); break; \
                    case STATUS_OBJECT_PATH_INVALID: printf("STATUS_OBJECT_PATH_INVALID"); break; \
                    case STATUS_OBJECT_PATH_NOT_FOUND: printf("STATUS_OBJECT_PATH_NOT_FOUND"); break; \
                    case STATUS_OBJECT_PATH_SYNTAX_BAD: printf("STATUS_OBJECT_PATH_SYNTAX_BAD"); break; \
                    case STATUS_SECTION_TOO_BIG: printf("STATUS_SECTION_TOO_BIG"); break; \
                    case STATUS_SECTION_PROTECTION: printf("STATUS_SECTION_PROTECTION"); break; \
                    case STATUS_INVALID_PARAMETER: printf("STATUS_INVALID_PARAMETER"); break; \
                    case STATUS_INVALID_PARAMETER_1: printf("STATUS_INVALID_PARAMETER_1"); break; \
                    case STATUS_INVALID_PARAMETER_2: printf("STATUS_INVALID_PARAMETER_2"); break; \
                    case STATUS_INVALID_PARAMETER_3: printf("STATUS_INVALID_PARAMETER_3"); break; \
                    case STATUS_INVALID_PARAMETER_4: printf("STATUS_INVALID_PARAMETER_4"); break; \
                    case STATUS_INVALID_PARAMETER_5: printf("STATUS_INVALID_PARAMETER_5"); break; \
                    case STATUS_INVALID_PARAMETER_6: printf("STATUS_INVALID_PARAMETER_6"); break; \
                    case STATUS_NO_SUCH_FILE: printf("STATUS_NO_SUCH_FILE"); break; \
                    case STATUS_INVALID_DEVICE_REQUEST: printf("STATUS_INVALID_DEVICE_REQUEST"); break; \
                    case STATUS_ILLEGAL_FUNCTION: printf("STATUS_ILLEGAL_FUNCTION"); break; \
                    case STATUS_INVALID_HANDLE: printf("STATUS_INVALID_HANDLE"); break; \
                    case STATUS_DATATYPE_MISALIGNMENT_ERROR: printf("STATUS_DATATYPE_MISALIGNMENT_ERROR"); break; \
                    case STATUS_OBJECT_NAME_COLLISION: printf("STATUS_OBJECT_NAME_COLLISION"); break; \
                    default: printf("unknown"); break; \
                }; \
                printf(" (0x%x)\n", _c_) \
}
#define DPrintMem(_b_, _s_) \
{ \
    for ( UINT64 _i_ = 0; _i_ < _s_; _i_+=0x10 ) \
    { \
        UINT64 _end_ = (_i_+0x10<_s_)?(_i_+0x10):(_s_); \
        ULONG _gap_ = (_i_+0x10<=_s_) ? 0 : ((0x10+_i_-_s_)*3); \
        printf("%p  ", (((PUINT8)_b_)+_i_)); \
         \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_++ ) \
        { \
            printf("%02x ", ((PUINT8)_b_)[_j_]); \
        } \
        for ( ULONG _j_ = 0; _j_ < _gap_; _j_++ ) \
        { \
            printf(" "); \
        } \
        printf("  "); \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_++ ) \
        { \
            if ( ((PUINT8)_b_)[_j_] < 0x20 || ((PUINT8)_b_)[_j_] > 0x7E || ((PUINT8)_b_)[_j_] == 0x25 ) \
            { \
                printf("."); \
            }  \
            else \
            { \
                printf("%c", ((PUINT8)_b_)[_j_]); \
            } \
        } \
        printf("\n"); \
    } \
}
#define DPrintBytes(_b_, _s_) \
{ \
    for ( UINT64 _i_ = 0; _i_ < _s_; _i_+=0x10 ) \
    { \
        UINT64 _end_ = (_i_+0x10<_s_)?(_i_+0x10):(_s_); \
         \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_++ ) \
        { \
            printf("%02x ", ((PUINT8)_b_)[_j_]); \
        } \
        printf("\n"); \
    } \
}
#else
#define DPrint(...)
#define DPrintW(...)
#define FPrint()
#define SPrint(_c_)
#define DPrintMem(_b_, _s_)
#define DPrintBytes(_b_, _s_)
#endif

#ifdef ERROR_PRINT
#define EPrint(...) \
{ \
                printf("[e] ");\
                printf(__VA_ARGS__); \
}
#define EPrintW(...) \
{ \
                wprintf(L"[e] ");\
                wprintf(__VA_ARGS__); \
}
#else
#define EPrint(...)
#define EPrintW(...)
#endif



#define PrintMemCols8(_b_, _s_) \
{ \
    for ( UINT64 _i_ = 0; _i_ < _s_; _i_+=0x10 ) \
    { \
        UINT64 _end_ = (_i_+0x10<_s_)?(_i_+0x10):(_s_); \
        ULONG _gap_ = (_i_+0x10<=_s_) ? 0 : (ULONG)((0x10+_i_-_s_)*3); \
        printf("%p  ", (((PUINT8)_b_)+_i_)); \
         \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_++ ) \
        { \
            printf("%02x ", ((PUINT8)_b_)[_j_]); \
        } \
        for ( ULONG _j_ = 0; _j_ < _gap_; _j_++ ) \
        { \
            printf(" "); \
        } \
        printf("  "); \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_++ ) \
        { \
            if ( ((PUINT8)_b_)[_j_] < 0x20 || ((PUINT8)_b_)[_j_] > 0x7E || ((PUINT8)_b_)[_j_] == 0x25 ) \
            { \
                printf("."); \
            }  \
            else \
            { \
                printf("%c", ((PUINT8)_b_)[_j_]); \
            } \
        } \
        printf("\n"); \
    } \
}

#define PrintMemCols16(_b_, _s_) \
{ \
    if ( _s_ % 2 != 0 ) _s_ = _s_ - 1; \
    \
    for ( UINT64 _i_ = 0; _i_ < _s_; _i_+=0x10 ) \
    { \
        UINT64 _end_ = (_i_+0x10<_s_)?(_i_+0x10):(_s_); \
        ULONG _gap_ = (_i_+0x10<=_s_) ? 0 : (ULONG)((0x10+_i_-_s_)/2*5); \
        printf("%p  ", (((PUINT8)_b_)+_i_)); \
         \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_+=2 ) \
        { \
            printf("%04x ", *(PUINT16)&(((PUINT8)_b_)[_j_])); \
        } \
        for ( ULONG _j_ = 0; _j_ < _gap_; _j_++ ) \
        { \
            printf(" "); \
        } \
        printf("  "); \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_+=2 ) \
        { \
            printf("%wc", *(PUINT16)&(((PUINT8)_b_)[_j_])); \
        } \
        printf("\n"); \
    } \
}

#define PrintMemCols32(_b_, _s_) \
{ \
    if ( _s_ % 4 != 0 ) _s_ = _s_ - (_s_ % 4); \
    \
    for ( UINT64 _i_ = 0; _i_ < _s_; _i_+=0x10 ) \
    { \
        UINT64 _end_ = (_i_+0x10<_s_)?(_i_+0x10):(_s_); \
        printf("%p  ", (((PUINT8)_b_)+_i_)); \
         \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_+=4 ) \
        { \
            printf("%08x ", *(PUINT32)&(((PUINT8)_b_)[_j_])); \
        } \
        printf("\n"); \
    } \
}

#define PrintMemCols64(_b_, _s_) \
{ \
    if ( _s_ % 8 != 0 ) _s_ = _s_ - (_s_ % 8); \
    \
    for ( UINT64 _i_ = 0; _i_ < _s_; _i_+=0x10 ) \
    { \
        UINT64 _end_ = (_i_+0x10<_s_)?(_i_+0x10):(_s_); \
        printf("%p  ", (((PUINT8)_b_)+_i_)); \
         \
        for ( UINT64 _j_ = _i_; _j_ < _end_; _j_+=8 ) \
        { \
            printf("%016llx ", *(PUINT64)&(((PUINT8)_b_)[_j_])); \
        } \
        printf("\n"); \
    } \
}

#define PrintMemBytes(_b_, _s_) \
{ \
    for ( UINT64 _i_ = 0; _i_ < _s_; _i_++ ) \
    { \
        printf("%02x ", ((PUINT8)_b_)[_i_]); \
    } \
    printf("\n"); \
}
