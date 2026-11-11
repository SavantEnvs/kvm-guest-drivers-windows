// Minimal Windows type layer so NetKVM/VirtIO sources build on Linux without editing upstream.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#ifndef _WIN64
#define _WIN64 1
#endif

typedef unsigned char UCHAR, *PUCHAR, BOOLEAN, UINT8;
typedef unsigned short USHORT, *PUSHORT, UINT16;
typedef unsigned int ULONG, *PULONG, UINT, UINT32;
typedef uint64_t ULONGLONG, UINT64, UINT_PTR, ULONG_PTR;
typedef int32_t LONG;
typedef int64_t LONGLONG;
typedef UINT32 *PUINT32;
typedef UINT16 *PUINT16;
typedef void VOID, *PVOID;
typedef const char *LPCSTR;
typedef int INT;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef union _LARGE_INTEGER_SHIM {
    struct { ULONG LowPart; LONG HighPart; };
    LONGLONG QuadPart;
} PHYSICAL_ADDRESS;

#ifdef __cplusplus
template <class T> static inline T min(T a, T b) { return a < b ? a : b; }
template <class T> static inline T max(T a, T b) { return a > b ? a : b; }
#else
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))
#define RtlZeroMemory(d, n)              memset((d), 0, (n))
#define RtlCopyMemory(d, s, n)           memcpy((d), (s), (n))
#define NdisZeroMemory(d, n)             memset((d), 0, (n))
#define NETKVM_ASSERT(x)                 assert(x)

#define __fallthrough __attribute__((fallthrough))
static inline USHORT RtlUshortByteSwap(USHORT v) { return (USHORT)((v << 8) | (v >> 8)); }
#define RTL_FIELD_SIZE(type, field)          (sizeof(((type *)0)->field))
#define RTL_SIZEOF_THROUGH_FIELD(type, field) (offsetof(type, field) + RTL_FIELD_SIZE(type, field))
#define ETH_IS_BROADCAST(Address)                                                                                      \
    ((((PUCHAR)(Address))[0] == ((UCHAR)0xff)) && (((PUCHAR)(Address))[1] == ((UCHAR)0xff)) &&                         \
     (((PUCHAR)(Address))[2] == ((UCHAR)0xff)) && (((PUCHAR)(Address))[3] == ((UCHAR)0xff)) &&                         \
     (((PUCHAR)(Address))[4] == ((UCHAR)0xff)) && (((PUCHAR)(Address))[5] == ((UCHAR)0xff)))
#define ETH_IS_MULTICAST(Address) ((BOOLEAN)(((PUCHAR)(Address))[0] & ((UCHAR)0x01)))
#define RtlPointerToOffset(Base, Pointer) ((ULONG)(((PUCHAR)(Pointer)) - ((PUCHAR)(Base))))
