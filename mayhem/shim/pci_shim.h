// Windows PCI config-space types (wdm.h / pci.h layout) for VirtIO/VirtIOPCIModern.c.
#pragma once
#include "win_types.h"

#define PCI_STATUS_CAPABILITIES_LIST 0x0010
#define PCI_MULTIFUNCTION 0x80
#define PCI_DEVICE_TYPE 0
#define PCI_BRIDGE_TYPE 1
#define PCI_CARDBUS_BRIDGE_TYPE 2
#define PCI_TYPE0_ADDRESSES 6
#define PCI_CAPABILITY_ID_VENDOR_SPECIFIC 0x09
#define PCI_ADDRESS_IO_SPACE 0x00000001
#define PCI_ADDRESS_IO_ADDRESS_MASK 0xfffffffc
#define PCI_ADDRESS_MEMORY_TYPE_MASK 0x00000006
#define PCI_ADDRESS_MEMORY_ADDRESS_MASK 0xfffffff0
#define PCI_TYPE_64BIT 4
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))

typedef struct _PCI_CAPABILITIES_HEADER {
    UCHAR CapabilityID;
    UCHAR Next;
} PCI_CAPABILITIES_HEADER;

typedef struct _PCI_COMMON_HEADER {
    USHORT VendorID, DeviceID, Command, Status;
    UCHAR RevisionID, ProgIf, SubClass, BaseClass, CacheLineSize, LatencyTimer, HeaderType, BIST;
    union {
        struct {
            ULONG BaseAddresses[PCI_TYPE0_ADDRESSES];
            ULONG CIS;
            USHORT SubVendorID, SubSystemID;
            ULONG ROMBaseAddress;
            UCHAR CapabilitiesPtr;
            UCHAR Reserved1[3];
            ULONG Reserved2;
            UCHAR InterruptLine, InterruptPin, MinimumGrant, MaximumLatency;
        } type0;
        struct {
            ULONG BaseAddresses[2];
            UCHAR PrimaryBus, SecondaryBus, SubordinateBus, SecondaryLatency;
            UCHAR IOBase, IOLimit;
            USHORT SecondaryStatus;
            USHORT MemoryBase, MemoryLimit, PrefetchBase, PrefetchLimit;
            ULONG PrefetchBaseUpper32, PrefetchLimitUpper32;
            USHORT IOBaseUpper16, IOLimitUpper16;
            UCHAR CapabilitiesPtr;
            UCHAR Reserved1[3];
            ULONG ROMBaseAddress;
            UCHAR InterruptLine, InterruptPin;
            USHORT BridgeControl;
        } type1;
        struct {
            ULONG SocketRegistersBaseAddress;
            UCHAR CapabilitiesPtr;
            UCHAR Reserved;
            USHORT SecondaryStatus;
            UCHAR PrimaryBus, SecondaryBus, SubordinateBus, SecondaryLatency;
            struct {
                ULONG Base, Limit;
            } Range[4];
            UCHAR InterruptLine, InterruptPin;
            USHORT BridgeControl;
        } type2;
    } u;
    UCHAR DeviceSpecific[192];
} PCI_COMMON_HEADER, *PPCI_COMMON_HEADER;
