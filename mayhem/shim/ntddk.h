// Stand-in for <ntddk.h> so VirtIO/*.c build on Linux (LP64) without editing upstream.
// VirtIO/linux/types.h is skipped through its include guard because its u32 is `unsigned long`
// (64-bit here); the same names are defined below with the Windows widths.
#pragma once
#include "win_types.h"

#define _LINUX_TYPES_H
#define __bitwise__
typedef unsigned char u8, __u8;
typedef unsigned short u16, __u16, __le16;
typedef unsigned int __u32, __le32;
/* VirtIORing.c defines virtio_get_indirect_page_capacity() as returning u32 while virtio_pci.h declares it
   `unsigned long` (identical on Windows); that one TU is built with -DMAYHEM_U32_LONG to keep them compatible. */
#ifdef MAYHEM_U32_LONG
typedef unsigned long u32;
#else
typedef unsigned int u32;
#endif
typedef uint64_t u64, __u64;

typedef int NTSTATUS;
#define STATUS_SUCCESS       ((NTSTATUS)0)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_DEVICE_NOT_CONNECTED ((NTSTATUS)0xC000009DL)
#define NT_SUCCESS(s)        ((NTSTATUS)(s) >= 0)

#define __forceinline inline __attribute__((always_inline))
#define PAGE_SIZE 4096

#define ASSERT(x)            ((void)0) /* release-build semantics: the shipped drivers compile ASSERT out */
#define KeMemoryBarrier()    __sync_synchronize()
extern void mayhem_bugcheck(unsigned int code);
#define KeBugCheck(code)     mayhem_bugcheck(code)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011L)
#define ROUND_TO_PAGES(Size) (((size_t)(Size) + PAGE_SIZE - 1) & ~((size_t)PAGE_SIZE - 1))
#include "pci_shim.h"

/* kdebugprint.h's DPrintf(level, ("msg")) relies on MSVC dropping the comma before an empty __VA_ARGS__;
   include it first (it is #pragma once), then redefine the macro with the GNU spelling. */
#include "kdebugprint.h"
#undef DPrintf
#define DPrintf(Level, MSG, ...)                      \
    if ((!bDebugPrint) || Level > virtioDebugLevel) { \
    } else                                            \
        VirtioDebugPrintProc(MSG, ##__VA_ARGS__)
