/* libFuzzer harness for NetKVM/Common/sw_offload.cpp, following the driver's receive path
 * (CParaNdisRX::ProcessReceivedPacket -> ParaNdis_PrepareReceivedPacket -> ParaNdis_CheckRxChecksum).
 * Input: [0..1] selects the checksum request flags the way ParaNdis_CheckRxChecksum builds them,
 * [2..] Ethernet frame. */
#include "ndis56common_shim.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// The flags ParaNdis_CheckRxChecksum computes: the IP header check; then either "device needs checksum"
// (fix up TCP/UDP checksums too) or the per-protocol verify-only requests.
static ULONG rx_checksum_flags(unsigned sel)
{
    ULONG flags = (sel & 1) ? static_cast<ULONG>(tPacketOffloadRequest::pcrIpChecksum) : 0;
    if (sel & 2)
    {
        flags |= tPacketOffloadRequest::pcrFixXxpChecksum | tPacketOffloadRequest::pcrTcpChecksum |
                 tPacketOffloadRequest::pcrUdpChecksum;
    }
    else
    {
        flags |= ((sel >> 2) & 0xF) << 1; // pcrTcpV4, pcrUdpV4, pcrTcpV6, pcrUdpV6
    }
    return flags;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2)
    {
        return -1;
    }
    const ULONG flags = rx_checksum_flags(data[0] | (data[1] << 8));
    const uint8_t *pkt = data + 2;
    const size_t len = size - 2;

    // RX data lives in PAGE_SIZE-granular blocks (CParaNdisRX::ProcessReceivedPacket reads the frame from
    // PhysicalPages[FirstRxDataPage] + DataStartOffset). Model that block: a calloc'd whole number of pages,
    // frame at the start, zero-filled tail, so an over-read stays in the page as it does in the driver and only
    // a read past the page is an ASan defect.
    const size_t block = ((len ? len : 1) + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;

    // Receive-path classification (ParaNdis_RX.cpp: ParaNdis_AnalyzeReceivedPacket on the data pointer).
    {
        uint8_t *buf = static_cast<uint8_t *>(calloc(block, 1));
        memcpy(buf, pkt, len);
        NET_PACKET_INFO info;
        ParaNdis_AnalyzeReceivedPacket(buf, static_cast<ULONG>(len), &info);
        free(buf);
    }

    // TX path, UDP CSO: CNB::CopyHeaders copies min(MaxSize, MAX_HEADERS_SIZE_FOR_CSO, data length) bytes of the
    // frame into the descriptor's headers page (CTXDescriptor::Create allocates PAGE_SIZE for it; layout in
    // CTXHeaders::Initialize: ALIGN_UP(ETH_PRIORITY_HEADER_SIZE, 8) priority area, nVirtioHeaderSize
    // virtio header, then the Ethernet headers). CNB::QueryL4HeaderOffset then calls ParaNdis_ReviewIPPacket on
    // EthHeaders + ipHeaderOffset with size GetDataLength() (the whole frame, not the copied length) and
    // verifyLength FALSE. So the analysis may read past the copy, into the rest of that page, which is zero here.
    {
        const size_t prio = 8;
        const size_t virtio_hdr = 12; // sizeof(virtio_net_hdr_mrg_rxbuf)
        const size_t eth_off = prio + virtio_hdr;
        const size_t max_eth = PAGE_SIZE - eth_off;
        const size_t ncopy = len < MAX_HEADERS_SIZE_FOR_CSO ? len : MAX_HEADERS_SIZE_FOR_CSO;
        uint8_t *page = static_cast<uint8_t *>(calloc(PAGE_SIZE, 1));
        memcpy(page + eth_off, pkt, ncopy < max_eth ? ncopy : max_eth);
        ParaNdis_ReviewIPPacket(page + eth_off + ETH_HEADER_SIZE, static_cast<ULONG>(len), FALSE, "fuzz");
        free(page);
    }

    // RX path as the driver runs it, on the same page-granular block: the frame's headers sit in the first
    // page and the tail of the page is zeros. The block is at least ETH_MIN_PACKET_SIZE plus the VLAN tag
    // because padding writes there.
    {
        uint8_t *p0 = static_cast<uint8_t *>(calloc(block, 1));
        memcpy(p0, pkt, len);

        NET_PACKET_INFO info;
        // A frame the analysis rejects is dropped by the driver before checksum handling.
        if (ParaNdis_AnalyzeReceivedPacket(p0, static_cast<ULONG>(len), &info))
        {
            ULONG stripped = 0;
            if (info.hasVlanHeader)
            {
                stripped = ParaNdis_StripVlanHeaderMoveHead(&info);
            }
            ParaNdis_PadPacketToMinimalLength(&info);

            // ParaNdis_CheckRxChecksum: only for IP frames, length and offset relative to the data start
            // (after the stripped VLAN tag), verifyLength TRUE as ParaNdis_PrepareReceivedPacket passes.
            if (info.isIP4 || info.isIP6)
            {
                tCompletePhysicalAddress pages[1];
                memset(pages, 0, sizeof(pages));
                pages[0].Virtual = p0;
                pages[0].size = static_cast<ULONG>(block);
                ParaNdis_CheckSumVerify(pages,
                                        info.dataLength - ETH_HEADER_SIZE,
                                        stripped + ETH_HEADER_SIZE,
                                        flags,
                                        TRUE,
                                        "fuzz");
            }
        }
        free(p0);
    }
    return 0;
}
