// Force-included into sw_offload.cpp. Defining the upstream include guard turns NetKVM/Common/ndis56common.h
// (which needs the NDIS headers) into an empty file; the few types sw_offload.cpp needs are restated here
// verbatim from that header.
#pragma once
#define PARANDIS_56_COMMON_H
#include "win_types.h"
#include "ethernetutils.h"
#include "kdebugprint.h"

#define PARANDIS_SUPPORT_RSS 0

typedef struct _tagCompletePhysicalAddress
{
    PHYSICAL_ADDRESS Physical;
    PVOID Virtual;
    ULONG size;
} tCompletePhysicalAddress;

typedef struct _tagNET_PACKET_INFO
{
    struct
    {
        int isBroadcast : 1;
        int isMulticast : 1;
        int isUnicast : 1;
        int hasVlanHeader : 1;
        int isIP4 : 1;
        int isIP6 : 1;
        int isTCP : 1;
        int isUDP : 1;
        int isFragment : 1;
    };

    struct
    {
        UINT32 UserPriority : 3;
        UINT32 VlanId : 12;
    } Vlan;

    ULONG L2HdrLen;
    ULONG L3HdrLen;
    ULONG L2PayloadLen;
    ULONG ip6HomeAddrOffset;
    ULONG ip6DestAddrOffset;

    PUCHAR ethDestAddr;

    PVOID headersBuffer;
    ULONG dataLength;
} NET_PACKET_INFO, *PNET_PACKET_INFO;

typedef enum class _tagppResult
{
    ppresNotTested = 0,
    ppresNotIP = 1,
    ppresIPV4 = 2,
    ppresIPV6 = 3,
    ppresIPTooShort = 1,
    ppresPCSOK = 1,
    ppresCSOK = 2,
    ppresCSBad = 3,
    ppresXxpOther = 1,
    ppresXxpKnown = 2,
    ppresXxpIncomplete = 3,
    ppresIsTCP = 0,
    ppresIsUDP = 1,
} ppResult;

inline bool operator==(ULONG a, ppResult b) { return a == static_cast<ULONG>(b); }
inline bool operator!=(ULONG a, ppResult b) { return a != static_cast<ULONG>(b); }

typedef union _tagTcpIpPacketParsingResult {
    struct
    {
        ULONG ipStatus : 2;
        ULONG ipCheckSum : 2;
        ULONG xxpCheckSum : 2;
        ULONG xxpStatus : 2;
        ULONG xxpFull : 1;
        ULONG TcpUdp : 1;
        ULONG fixedIpCS : 1;
        ULONG fixedXxpCS : 1;
        ULONG IsFragment : 1;
        ULONG reserved : 3;
        ULONG ipHeaderSize : 8;
        ULONG XxpIpHeaderSize : 8;
    };
    ULONG value;
} tTcpIpPacketParsingResult;

typedef enum class _tagPacketOffloadRequest
{
    pcrIpChecksum = (1 << 0),
    pcrTcpV4Checksum = (1 << 1),
    pcrUdpV4Checksum = (1 << 2),
    pcrTcpV6Checksum = (1 << 3),
    pcrUdpV6Checksum = (1 << 4),
    pcrTcpChecksum = (pcrTcpV4Checksum | pcrTcpV6Checksum),
    pcrUdpChecksum = (pcrUdpV4Checksum | pcrUdpV6Checksum),
    pcrAnyChecksum = (pcrIpChecksum | pcrTcpV4Checksum | pcrUdpV4Checksum | pcrTcpV6Checksum | pcrUdpV6Checksum),
    pcrLSO = (1 << 5),
    pcrIsIP = (1 << 6),
    pcrFixIPChecksum = (1 << 7),
    pcrFixPHChecksum = (1 << 8),
    pcrFixTcpV4Checksum = (1 << 9),
    pcrFixUdpV4Checksum = (1 << 10),
    pcrFixTcpV6Checksum = (1 << 11),
    pcrFixUdpV6Checksum = (1 << 12),
    pcrFixXxpChecksum = (pcrFixTcpV4Checksum | pcrFixUdpV4Checksum | pcrFixTcpV6Checksum | pcrFixUdpV6Checksum),
    pcrPriorityTag = (1 << 13),
    pcrNoIndirect = (1 << 14)
} tPacketOffloadRequest;

inline ULONG operator|(tPacketOffloadRequest a, tPacketOffloadRequest b) { return static_cast<ULONG>(a) | static_cast<ULONG>(b); }
inline ULONG operator|(ULONG a, tPacketOffloadRequest b) { return a | static_cast<ULONG>(b); }
inline ULONG &operator|=(ULONG &a, tPacketOffloadRequest b) { return a |= static_cast<ULONG>(b); }
inline ULONG operator&(tPacketOffloadRequest a, tPacketOffloadRequest b) { return static_cast<ULONG>(a) & static_cast<ULONG>(b); }
inline ULONG operator&(ULONG a, tPacketOffloadRequest b) { return a & static_cast<ULONG>(b); }

tTcpIpPacketParsingResult ParaNdis_CheckSumVerify(tCompletePhysicalAddress *pDataPages,
                                                  ULONG ulDataLength,
                                                  ULONG ulStartOffset,
                                                  ULONG flags,
                                                  BOOLEAN verifyLength,
                                                  LPCSTR caller);
USHORT CheckSumCalculator(PVOID buffer, ULONG len);
tTcpIpPacketParsingResult ParaNdis_ReviewIPPacket(PVOID buffer, ULONG size, BOOLEAN verityLength, LPCSTR caller);
BOOLEAN ParaNdis_AnalyzeReceivedPacket(PVOID headersBuffer, ULONG dataLength, PNET_PACKET_INFO packetInfo);
ULONG ParaNdis_StripVlanHeaderMoveHead(PNET_PACKET_INFO packetInfo);
VOID ParaNdis_PadPacketToMinimalLength(PNET_PACKET_INFO packetInfo);
