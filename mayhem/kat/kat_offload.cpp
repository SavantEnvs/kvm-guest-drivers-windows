// Known-answer tests for NetKVM/Common/sw_offload.cpp. Packets are built here with an independent RFC 1071
// checksum; every line printed is compared by mayhem/test.sh against the expected text.
#include "ndis56common_shim.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>

typedef std::vector<uint8_t> Bytes;

static void put16(Bytes &b, unsigned v) { b.push_back(v >> 8); b.push_back(v & 0xFF); }

static uint16_t rfc1071(const uint8_t *p, size_t n, uint32_t sum = 0)
{
    for (size_t i = 0; i + 1 < n; i += 2) sum += (p[i] << 8) | p[i + 1];
    if (n & 1) sum += p[n - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static Bytes eth(const uint8_t dst0, unsigned type)
{
    Bytes b = {dst0, 0x22, 0x33, 0x44, 0x55, 0x66, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    put16(b, type);
    return b;
}

static Bytes ip4(unsigned proto, const Bytes &l4, unsigned frag = 0)
{
    Bytes h = {0x45, 0, 0, 0};
    unsigned total = 20 + l4.size();
    h[2] = total >> 8; h[3] = total & 0xFF;
    put16(h, 0x1234); put16(h, frag);
    h.push_back(64); h.push_back(proto); put16(h, 0);
    const uint8_t addrs[] = {192, 168, 1, 1, 192, 168, 1, 2};
    h.insert(h.end(), addrs, addrs + 8);
    unsigned cs = rfc1071(h.data(), 20);
    h[10] = cs >> 8; h[11] = cs & 0xFF;
    h.insert(h.end(), l4.begin(), l4.end());
    return h;
}

static Bytes tcp_seg(size_t payload, bool v6)
{
    Bytes t;
    put16(t, 1234); put16(t, 80);
    const uint8_t seqack[] = {0, 0, 0, 1, 0, 0, 0, 2};
    t.insert(t.end(), seqack, seqack + 8);
    put16(t, 0x5018); put16(t, 0x2000); put16(t, 0); put16(t, 0);
    for (size_t i = 0; i < payload; i++) t.push_back('a' + i % 26);
    (void)v6;
    return t;
}

static Bytes udp_seg(size_t payload)
{
    Bytes u;
    put16(u, 5000); put16(u, 53); put16(u, 8 + payload); put16(u, 0);
    for (size_t i = 0; i < payload; i++) u.push_back('A' + i % 26);
    return u;
}

static void fix_l4_csum(Bytes &pkt, size_t ipoff, bool v6, unsigned proto, size_t l4off)
{
    uint32_t sum = 0;
    size_t l4len = pkt.size() - l4off;
    const uint8_t *ip = pkt.data() + ipoff;
    size_t alen = v6 ? 32 : 8;
    const uint8_t *addr = v6 ? ip + 8 : ip + 12;
    for (size_t i = 0; i < alen; i += 2) sum += (addr[i] << 8) | addr[i + 1];
    sum += proto + l4len;
    size_t csoff = l4off + (proto == 6 ? 16 : 6);
    pkt[csoff] = pkt[csoff + 1] = 0;
    unsigned cs = rfc1071(pkt.data() + l4off, l4len, sum);
    if (proto == 17 && cs == 0) cs = 0xFFFF;
    pkt[csoff] = cs >> 8; pkt[csoff + 1] = cs & 0xFF;
}

static Bytes ip6(unsigned next, const Bytes &rest)
{
    Bytes h = {0x60, 0, 0, 0};
    put16(h, rest.size());
    h.push_back(next); h.push_back(64);
    for (int i = 0; i < 16; i++) h.push_back(i == 0 ? 0xFE : (i == 15 ? 1 : 0));
    for (int i = 0; i < 16; i++) h.push_back(i == 0 ? 0xFE : (i == 15 ? 2 : 0));
    h.insert(h.end(), rest.begin(), rest.end());
    return h;
}

static Bytes cat(Bytes a, const Bytes &b) { a.insert(a.end(), b.begin(), b.end()); return a; }

static Bytes tcp4_frame(size_t payload = 12)
{
    Bytes f = cat(eth(0x00, 0x0800), ip4(6, tcp_seg(payload, false)));
    fix_l4_csum(f, 14, false, 6, 34);
    return f;
}

static void show_info(const char *name, const Bytes &frame)
{
    Bytes copy = frame;
    NET_PACKET_INFO i;
    BOOLEAN ok = ParaNdis_AnalyzeReceivedPacket(copy.data(), static_cast<ULONG>(copy.size()), &i);
    printf("%s: ok=%d bcast=%d mcast=%d ucast=%d vlan=%d ip4=%d ip6=%d tcp=%d udp=%d frag=%d l2=%u l3=%u vid=%u prio=%u\n",
           name, ok, i.isBroadcast, i.isMulticast, i.isUnicast, i.hasVlanHeader, i.isIP4, i.isIP6, i.isTCP, i.isUDP,
           i.isFragment, i.L2HdrLen, i.L3HdrLen, (unsigned)i.Vlan.VlanId, (unsigned)i.Vlan.UserPriority);
}

static tTcpIpPacketParsingResult verify(Bytes &frame, ULONG flags, bool verifyLen = true)
{
    tCompletePhysicalAddress page;
    memset(&page, 0, sizeof(page));
    page.Virtual = frame.data();
    page.size = static_cast<ULONG>(frame.size());
    return ParaNdis_CheckSumVerify(&page, static_cast<ULONG>(frame.size() - 14), 14, flags, verifyLen, "kat");
}

static void show_res(const char *name, tTcpIpPacketParsingResult r)
{
    printf("%s: ip=%u ipcs=%u xxpcs=%u xxp=%u full=%u udp=%u fixIp=%u fixXxp=%u frag=%u iphl=%u\n", name, r.ipStatus,
           r.ipCheckSum, r.xxpCheckSum, r.xxpStatus, r.xxpFull, r.TcpUdp, r.fixedIpCS, r.fixedXxpCS, r.IsFragment,
           r.ipHeaderSize);
}

int main()
{
    const ULONG any = static_cast<ULONG>(tPacketOffloadRequest::pcrAnyChecksum);

    Bytes t4 = tcp4_frame();
    show_info("analyze_tcp4", t4);
    show_res("verify_tcp4_good", verify(t4, any));
    show_res("review_tcp4", ParaNdis_ReviewIPPacket(t4.data() + 14, t4.size() - 14, TRUE, "kat"));

    Bytes t4bad = t4;
    t4bad[34 + 16] ^= 0x55;
    show_res("verify_tcp4_badcs", verify(t4bad, any));

    Bytes t4fix = t4bad;
    show_res("verify_tcp4_fix",
             verify(t4fix, tPacketOffloadRequest::pcrTcpV4Checksum | tPacketOffloadRequest::pcrFixTcpV4Checksum));
    printf("fixed_tcp4_csum_matches_original=%d\n", t4fix == t4);

    Bytes t4ipbad = t4;
    t4ipbad[14 + 10] ^= 0x01;
    show_res("verify_ip4_badcs", verify(t4ipbad, any));

    Bytes u4 = cat(eth(0x00, 0x0800), ip4(17, udp_seg(20)));
    fix_l4_csum(u4, 14, false, 17, 34);
    show_info("analyze_udp4", u4);
    show_res("verify_udp4_good", verify(u4, any));

    Bytes u4bc = u4;
    for (int i = 0; i < 6; i++) u4bc[i] = 0xFF;
    show_info("analyze_udp4_bcast", u4bc);
    Bytes u4mc = u4;
    u4mc[0] = 0x01;
    show_info("analyze_udp4_mcast", u4mc);

    Bytes fr = cat(eth(0x00, 0x0800), ip4(6, tcp_seg(8, false), 0x2000));
    show_info("analyze_ip4_fragment", fr);

    Bytes t6 = cat(eth(0x00, 0x86DD), ip6(6, tcp_seg(10, true)));
    fix_l4_csum(t6, 14, true, 6, 54);
    show_info("analyze_tcp6", t6);
    show_res("verify_tcp6_good", verify(t6, any));
    Bytes t6bad = t6;
    t6bad[54 + 16] ^= 0xA5;
    show_res("verify_tcp6_badcs", verify(t6bad, any));

    Bytes hbh = {17, 0, 1, 4, 0, 0, 0, 0};  // hop-by-hop: next=UDP, len 0 (8 bytes), PadN
    Bytes u6 = cat(eth(0x00, 0x86DD), ip6(0, cat(hbh, udp_seg(12))));
    fix_l4_csum(u6, 14, true, 17, 14 + 40 + 8);
    show_info("analyze_udp6_hopbyhop", u6);

    Bytes vl = {0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x02, 0, 0, 0, 0, 1, 0x81, 0x00, 0xA1, 0x23, 0x08, 0x00};
    Bytes vlf = cat(vl, ip4(17, udp_seg(8)));
    show_info("analyze_vlan_udp4", vlf);

    Bytes shortf(t4.begin(), t4.begin() + 14 + 12);
    show_info("analyze_truncated_ip4", shortf);
    Bytes arp = cat(eth(0xFF, 0x0806), Bytes(28, 0));
    show_info("analyze_arp", arp);

    printf("rfc1071_selfcheck=%04x\n", rfc1071(reinterpret_cast<const uint8_t *>("\x00\x01\xf2\x03\xf4\xf5\xf6\xf7"), 8));
    return 0;
}
