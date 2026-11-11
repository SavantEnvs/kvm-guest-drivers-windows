// Stand-ins for the WDF/HID/WMI headers precomp.h pulls in, so vioinput/sys/Hid*.c build on Linux unmodified.
#pragma once
#include "win_types.h"
#include <stdarg.h>

#include <limits.h>
#undef LONG_MAX
#define LONG_MAX 2147483647L
#define MAXUCHAR 0xff
typedef uint64_t *PUINT64;
typedef char CHAR;
typedef size_t SIZE_T;
typedef void *WDFCMRESLIST;
typedef struct { void *p; } RTL_BITMAP;
typedef struct { ULONG Data1; } GUID;
typedef short SHORT;
typedef unsigned long ULONG32_SHIM;
typedef const void *PCVOID;
typedef void *WDFOBJECT, *WDFDRIVER, *WDFDEVICE, *WDFQUEUE, *WDFREQUEST, *WDFINTERRUPT, *WDFSPINLOCK,
    *WDFDMAENABLER, *WDFCOLLECTION, *WDFDMATRANSACTION, *WDFMEMORY, *WDFTIMER, *WDFWORKITEM, *WDFFILEOBJECT;
typedef void *PWDFDEVICE_INIT, *PDEVICE_OBJECT, *PDRIVER_OBJECT, *PUNICODE_STRING, *PSCATTER_GATHER_LIST;
typedef struct { void *Next; } SINGLE_LIST_ENTRY;
typedef struct { void *Context; } BUS_INTERFACE_STANDARD;
typedef struct { void *UserBuffer; } IRP, *PIRP;
typedef struct { struct { struct { size_t OutputBufferLength, InputBufferLength; } DeviceIoControl; } Parameters; } WDF_REQUEST_PARAMETERS;
#define WDF_REQUEST_PARAMETERS_INIT(p) memset((p), 0, sizeof(*(p)))
#define UNREFERENCED_PARAMETER(p) ((void)(p))
#define FORCEINLINE static inline
typedef LONG *PLONG;
#define IOCTL_HID_GET_DEVICE_DESCRIPTOR 1
#define IOCTL_HID_GET_DEVICE_ATTRIBUTES 2
#define IOCTL_HID_GET_REPORT_DESCRIPTOR 3
#define IOCTL_HID_READ_REPORT 4
#define IOCTL_HID_WRITE_REPORT 5
#define IOCTL_HID_GET_FEATURE 6
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE);
void WdfRequestComplete(WDFREQUEST, NTSTATUS);
PIRP WdfRequestWdmGetIrp(WDFREQUEST);
void WdfRequestSetInformation(WDFREQUEST, ULONG_PTR);
void WdfRequestGetParameters(WDFREQUEST, WDF_REQUEST_PARAMETERS *);
NTSTATUS WdfRequestRetrieveOutputMemory(WDFREQUEST, WDFMEMORY *);
NTSTATUS WdfRequestForwardToIoQueue(WDFREQUEST, WDFQUEUE);
NTSTATUS WdfIoQueueRetrieveNextRequest(WDFQUEUE, WDFREQUEST *);
PVOID WdfMemoryGetBuffer(WDFMEMORY, size_t *);
NTSTATUS WdfMemoryCopyFromBuffer(WDFMEMORY, size_t, PVOID, size_t);
void WdfSpinLockAcquire(WDFSPINLOCK);
void WdfSpinLockRelease(WDFSPINLOCK);
typedef enum { NonPagedPool = 0 } POOL_TYPE;
#define DEFINE_GUID(n, a, b, c, d1, d2, d3, d4, d5, d6, d7, d8) extern const GUID n
#define IN
#define OUT
#define CONST const
#define MINCHAR  0x80
#define MAXCHAR  0x7f
#define MINSHORT 0x8000
#define MAXSHORT 0x7fff
#define STATUS_NONE_MAPPED ((NTSTATUS)0xC0000073L)
#define STATUS_INVALID_BUFFER_SIZE ((NTSTATUS)0xC0000206L)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#define STATUS_PENDING ((NTSTATUS)0x00000103L)

#define RtlFillMemory(d, n, f) memset((d), (f), (n))
#define RtlCopyBytes(d, s, n)  memcpy((d), (s), (n))
#define ExAllocatePoolUninitialized(t, n, tag) malloc(n)
#define ExFreePoolWithTag(p, tag)              free(p)
#define sprintf_s(b, n, ...)                   snprintf((b), (n), __VA_ARGS__)
#define RtlStringCbVPrintfA(b, n, f, a)        vsnprintf((b), (n), (f), (a))
static inline unsigned char BitScanForward(ULONG *Index, ULONG Mask)
{
    if (!Mask) return 0;
    *Index = (ULONG)__builtin_ctz(Mask);
    return 1;
}

#define EVT_WDF(name, ...) typedef void name(__VA_ARGS__)
typedef NTSTATUS EVT_WDF_DRIVER_DEVICE_ADD(WDFDRIVER, PWDFDEVICE_INIT);
typedef BOOLEAN EVT_WDF_INTERRUPT_ISR(WDFINTERRUPT, ULONG);
typedef void EVT_WDF_INTERRUPT_DPC(WDFINTERRUPT, WDFOBJECT);
typedef NTSTATUS EVT_WDF_INTERRUPT_ENABLE(WDFINTERRUPT, WDFDEVICE);
typedef NTSTATUS EVT_WDF_INTERRUPT_DISABLE(WDFINTERRUPT, WDFDEVICE);

#define WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(T, name) static inline T *name(void *h) { return (T *)h; }

typedef struct _HID_DESCRIPTOR_LIST_ENTRY
{
    UCHAR bReportType;
    USHORT wReportLength;
} __attribute__((packed)) HID_DESCRIPTOR_LIST_ENTRY;
typedef struct _HID_DESCRIPTOR
{
    UCHAR bLength;
    UCHAR bDescriptorType;
    USHORT bcdHID;
    UCHAR bCountry;
    UCHAR bNumDescriptors;
    HID_DESCRIPTOR_LIST_ENTRY DescriptorList[1];
} __attribute__((packed)) HID_DESCRIPTOR, *PHID_DESCRIPTOR;
typedef struct _HID_DEVICE_ATTRIBUTES
{
    ULONG Size;
    USHORT VendorID;
    USHORT ProductID;
    USHORT VersionNumber;
    USHORT Reserved[11];
} HID_DEVICE_ATTRIBUTES, *PHID_DEVICE_ATTRIBUTES;
typedef struct _HID_XFER_PACKET
{
    PUCHAR reportBuffer;
    ULONG reportBufferLen;
    UCHAR reportId;
} HID_XFER_PACKET, *PHID_XFER_PACKET;
#define HID_USAGE_PAGE_CONSUMER 0x0C

#define HID_USAGE_PAGE_GENERIC 0x01
#define HID_USAGE_PAGE_SIMULATION 0x02
#define HID_USAGE_PAGE_KEYBOARD 0x07
#define HID_USAGE_PAGE_LED 0x08
#define HID_USAGE_PAGE_BUTTON 0x09
#define HID_USAGE_PAGE_DIGITIZER 0x0D
#define HID_USAGE_GENERIC_POINTER 0x01
#define HID_USAGE_GENERIC_MOUSE 0x02
#define HID_USAGE_GENERIC_JOYSTICK 0x04
#define HID_USAGE_GENERIC_KEYBOARD 0x06
#define HID_USAGE_GENERIC_X 0x30
#define HID_USAGE_GENERIC_Y 0x31
#define HID_USAGE_GENERIC_Z 0x32
#define HID_USAGE_GENERIC_RX 0x33
#define HID_USAGE_GENERIC_RY 0x34
#define HID_USAGE_GENERIC_RZ 0x35
#define HID_USAGE_GENERIC_SLIDER 0x36
#define HID_USAGE_GENERIC_WHEEL 0x38
#define HID_USAGE_GENERIC_VX 0x40
#define HID_USAGE_GENERIC_VY 0x41
#define HID_USAGE_GENERIC_RESOLUTION_MULTIPLIER 0x48
#define HID_USAGE_KEYBOARD_ROLLOVER 0x01
#define HID_USAGE_LED_NUM_LOCK 0x01
#define HID_USAGE_LED_CAPS_LOCK 0x02
#define HID_USAGE_LED_SCROLL_LOCK 0x03
#define HID_USAGE_LED_COMPOSE 0x04
#define HID_USAGE_LED_KANA 0x05
#define HID_USAGE_LED_MUTE 0x09
#define HID_USAGE_LED_STAND_BY 0x0C
#define HID_USAGE_LED_MESSAGE_WAITING 0x17
#define HID_USAGE_LED_GENERIC_INDICATOR 0x4B
#define HID_USAGE_CONSUMERCTRL 0x01
#define HID_USAGE_CONSUMER_AC_PAN 0x0238
#define HID_USAGE_DIGITIZER_IN_RANGE 0x32
#define HID_USAGE_DIGITIZER_TIP_SWITCH 0x42
#define HID_USAGE_DIGITIZER_BARREL_SWITCH 0x44
#define HID_USAGE_SIMULATION_RUDDER 0xBA
#define HID_USAGE_SIMULATION_THROTTLE 0xBB

#define _In_
#define _Out_
#define _Inout_
#define _In_opt_
#define _Out_opt_
#define _Inout_opt_
#define _Use_decl_annotations_
#define _IRQL_requires_max_(x)
#define _Must_inspect_result_
#define _In_reads_bytes_(x)
#define _Out_writes_bytes_(x)
typedef struct { void *p; } DXGKRNL_INTERFACE, *PDXGKRNL_INTERFACE;
typedef struct { void *p; } CM_RESOURCE_LIST, *PCM_RESOURCE_LIST;
#define CM_RESOURCE_INTERRUPT_MESSAGE 0x2
#define _Outptr_result_bytebuffer_(x)
#define _IRQL_raises_(x)
#define _IRQL_requires_(x)
#define _IRQL_restores_global_(a, b)
#define _IRQL_saves_global_(a, b)
#define _When_(a, b)
typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY;
typedef ULONG_PTR KSPIN_LOCK;
