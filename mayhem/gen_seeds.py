#!/usr/bin/env python3
"""Regenerates the starter seeds under mayhem/<target>/testsuite/ (run from anywhere)."""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))


def w(target, name, data):
    d = os.path.join(HERE, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(bytes(data))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


MAC_D = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x56])
MAC_S = bytes([0x52, 0x54, 0, 0xAB, 0xCD, 0xEF])


def eth(et, payload, dst=MAC_D, vlan=None):
    if vlan is not None:
        return dst + MAC_S + struct.pack("!HHH", 0x8100, vlan, et) + payload
    return dst + MAC_S + struct.pack("!H", et) + payload


def ip4(proto, l4, ihl_words=5, frag=0, src=bytes([10, 0, 0, 1]), dst=bytes([10, 0, 0, 2]), bad=False):
    opts = b"\x01" * (4 * (ihl_words - 5))
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl_words, 0, 20 + len(opts) + len(l4), 0x1234, frag, 64, proto, 0, src, dst) + opts
    c = csum(hdr)
    if bad:
        c ^= 0x5A5A
    return hdr[:10] + struct.pack("!H", c) + hdr[12:] + l4


def pseudo4(proto, l4, src=bytes([10, 0, 0, 1]), dst=bytes([10, 0, 0, 2])):
    return src + dst + struct.pack("!BBH", 0, proto, len(l4))


def tcp(payload, ph, bad=False):
    h = struct.pack("!HHIIBBHHH", 1234, 80, 1, 0, 0x50, 0x18, 65535, 0, 0) + payload
    c = csum(ph + h)
    if bad:
        c ^= 0x1111
    return h[:16] + struct.pack("!H", c) + h[18:]


def udp(payload, ph, bad=False):
    h = struct.pack("!HHHH", 5000, 53, 8 + len(payload), 0) + payload
    c = csum(ph + h) or 0xFFFF
    if bad:
        c ^= 0x2222
    return h[:6] + struct.pack("!H", c) + h[8:]


def ip6(nh, l4, ext=b""):
    return struct.pack("!IHBB16s16s", 0x60000000, len(ext) + len(l4), nh, 64,
                       bytes([0xFE, 0x80] + [0] * 13 + [1]), bytes([0xFE, 0x80] + [0] * 13 + [2])) + ext + l4


def pseudo6(nh, l4):
    return bytes([0xFE, 0x80] + [0] * 13 + [1]) + bytes([0xFE, 0x80] + [0] * 13 + [2]) + struct.pack("!IBBBB", len(l4), 0, 0, 0, nh)


def nk(flags, frame):
    return bytes([flags & 0xFF, (flags >> 8) & 0xFF]) + frame


ALL = 0x3D  # IP check + per-protocol TCP/UDP v4/v6 verify-only requests (no "needs csum")
FIX = 0x03  # IP check + "device needs checksum": fix up TCP/UDP checksums
IP = ip4

t4 = tcp(b"hello world", pseudo4(6, b"x" * (20 + 11)))
u4 = udp(b"query", pseudo4(17, b"x" * 13))
t6l4 = tcp(b"v6data", pseudo6(6, b"x" * 26))
u6l4 = udp(b"v6udp!", pseudo6(17, b"x" * 14))

w("netkvm_offload", "tcp4_good", nk(ALL, eth(0x0800, IP(6, t4))))
w("netkvm_offload", "tcp4_bad_fix", nk(FIX, eth(0x0800, IP(6, tcp(b"hello world", pseudo4(6, b"x" * 31), bad=True), bad=True))))
w("netkvm_offload", "udp4_good", nk(ALL, eth(0x0800, IP(17, u4))))
w("netkvm_offload", "udp4_bad_fix", nk(FIX, eth(0x0800, IP(17, udp(b"query", pseudo4(17, b"x" * 13), bad=True)))))
w("netkvm_offload", "udp4_bcast", nk(ALL, eth(0x0800, IP(17, u4), dst=b"\xff" * 6)))
w("netkvm_offload", "udp4_mcast", nk(ALL, eth(0x0800, IP(17, u4), dst=bytes([1, 0, 0x5E, 0, 0, 1]))))
w("netkvm_offload", "tcp4_opts", nk(ALL, eth(0x0800, IP(6, t4, ihl_words=7))))
w("netkvm_offload", "ip4_frag", nk(ALL, eth(0x0800, IP(17, u4, frag=0x2000))))
w("netkvm_offload", "ip4_frag_off", nk(ALL, eth(0x0800, IP(17, u4, frag=0x00B9))))
w("netkvm_offload", "vlan_udp4", nk(ALL, eth(0x0800, IP(17, u4), vlan=0xA123)))
w("netkvm_offload", "tcp6_good", nk(ALL, eth(0x86DD, ip6(6, t6l4))))
w("netkvm_offload", "udp6_good", nk(ALL, eth(0x86DD, ip6(17, u6l4))))
w("netkvm_offload", "tcp6_bad_fix", nk(FIX, eth(0x86DD, ip6(6, tcp(b"v6data", pseudo6(6, b"x" * 26), bad=True)))))
w("netkvm_offload", "udp6_hopbyhop", nk(ALL, eth(0x86DD, ip6(0, u6l4, ext=bytes([17, 0, 1, 4, 0, 0, 0, 0])))))
w("netkvm_offload", "udp6_destopts_homeaddr",
  nk(ALL, eth(0x86DD, ip6(60, u6l4, ext=bytes([17, 2, 201, 16] + [0] * 12)))))
w("netkvm_offload", "udp6_routing2", nk(ALL, eth(0x86DD, ip6(43, u6l4, ext=bytes([17, 2, 2, 0, 0, 0, 0, 0] + [0] * 16)))))
w("netkvm_offload", "udp6_frag_hdr", nk(ALL, eth(0x86DD, ip6(44, u6l4, ext=bytes([17, 0, 0, 1, 0, 0, 0, 1])))))
w("netkvm_offload", "arp", nk(ALL, eth(0x0806, bytes(28), dst=b"\xff" * 6)))
w("netkvm_offload", "truncated_ip4", nk(ALL, eth(0x0800, IP(6, t4)[:14])))
w("netkvm_offload", "short_runt", nk(ALL, eth(0x0800, b"")))
big = udp(bytes(range(256)) * 2, pseudo4(17, b"x" * 520))
w("netkvm_offload", "udp4_large_split", nk(ALL, eth(0x0800, IP(17, big))))
huge = udp(bytes(range(256)) * 17, pseudo4(17, b"x" * 4360))
w("netkvm_offload", "udp4_two_pages", nk(ALL, eth(0x0800, IP(17, huge))))
w("netkvm_offload", "udp4_large_fix", nk(FIX, eth(0x0800, IP(17, big, bad=True))))

# virtio_ring: byte 0 = config (bit0 packed, bit1 event idx/suppression, bit2 legacy, bits3-5 log2(num)-1)
ADD = lambda cfg, *sg: [0, cfg] + [b for n in sg for b in struct.pack("<H", n)]
COMPLETE = lambda ln: [3] + list(struct.pack("<I", ln))
GET, HAS, KICKP, KICKA = [5], [7], [8], [9]
ENCB = lambda b: [10, b]
DISCB = [11]
DETACH = [13, 1]
SHUT = [13, 0]


def script(cfg, ops):
    return bytes([cfg]) + bytes(b for op in ops for b in op)


for name, cfg in (("split", 0b001000), ("split_event", 0b001010), ("split_legacy", 0b001100),
                  ("packed", 0b011001), ("packed_event", 0b011011), ("packed_small", 0b000001)):
    w("virtio_ring", name + "_roundtrip",
      script(cfg, [ADD(0x0A, 63, 1499), KICKP, HAS, COMPLETE(1564), HAS, GET, ENCB(1), DISCB]))
    w("virtio_ring", name + "_indirect",
      script(cfg, [ADD(0x4C, 100, 200, 300, 400), KICKA, COMPLETE(900), GET, HAS]))
    w("virtio_ring", name + "_fill_detach",
      script(cfg, [ADD(0x01, 10)] * 12 + [KICKP, COMPLETE(10), COMPLETE(10), GET, DETACH, DETACH, SHUT, ADD(0x09, 5, 6), GET]))
    w("virtio_ring", name + "_cb", script(cfg, [ADD(0x08, 32), ENCB(0), ENCB(1), DISCB, KICKP, COMPLETE(32), HAS, GET, ENCB(0)]))
w("virtio_ring", "split_raw_used", script(0b001000, [ADD(0x01, 8), [12, 1, 0, 0, 0xFF, 0x7F, 0xFF], GET]))
w("virtio_ring", "packed_poke", script(0b001001, [ADD(0x09, 8, 8), [12, 0, 0, 0, 7], COMPLETE(1), GET]))


# virtio_pci: 256 bytes of PCI config space, six u16 BAR sizes, a flag byte (bit0 = MSI-X), then the op script
def pci_cap(cfg, at, nxt, cfg_type, bar, off, length, mult=None):
    c = bytearray(cfg)
    ln = 20 if mult is not None else 16
    c[at:at + 16] = struct.pack("<BBBBB3xII", 9, nxt, ln, cfg_type, bar, off, length)
    if mult is not None:
        c[at + 16:at + 20] = struct.pack("<I", mult)
    return c


def pci_modern(notify_len=0x400, hdr_type=0, dev_cap=True):
    c = bytearray(256)
    c[0x06:0x08] = struct.pack("<H", 0x10)  # status: capabilities list
    c[0x0E] = hdr_type
    c[0x34] = 0x40
    c = pci_cap(c, 0x40, 0x50, 1, 0, 0, 56)
    c = pci_cap(c, 0x50, 0x64, 2, 0, 0x1000, notify_len, mult=4)
    c = pci_cap(c, 0x64, 0x74 if dev_cap else 0, 3, 0, 0x2000, 1)
    if dev_cap:
        c = pci_cap(c, 0x74, 0, 4, 0, 0x3000, 0x100)
    return c


POKE = lambda bar, off, v: [0, bar, off & 0xFF, off >> 8, v]
GETC = lambda off, n: [2, off, n]
SETC = lambda off, n: [3, off, n]
FINDQ = lambda n: [4, n - 1]
DELQ = [5]
QUERY = lambda i: [6, i]
SETF = lambda f: [7, 1] + list(struct.pack("<Q", f))
GETF = [7, 0]
STAT = lambda sub, arg=0: [8, sub, arg]
QVEC = lambda q, vec: [9, q, 1, vec & 0xFF, vec >> 8]
QSIZE = lambda q: [9, q, 0]
KICK = lambda q, ln: [10, q, ln & 0xFF, ln >> 8]
GETB = lambda q: [11, q]
V1 = 1 << 32


def pci_seed(name, cfg, bars, msix, ops):
    body = bytes(cfg) + b"".join(struct.pack("<H", b) for b in bars) + bytes([msix]) + bytes(b for op in ops for b in op)
    w("virtio_pci", name, body)


MODERN_OPS = [POKE(0, 18, 2), POKE(0, 24, 8), SETF(V1), FINDQ(2), KICK(0, 64), KICK(1, 1500), GETB(0), GETC(0, 4), GETC(4, 2),
              GETC(8, 8), SETC(0, 1), QSIZE(0), QUERY(1), STAT(2), STAT(3), GETF, DELQ]
pci_seed("modern_basic", pci_modern(), [0x4000, 0, 0, 0, 0, 0], 0, MODERN_OPS)
pci_seed("modern_msix", pci_modern(), [0x4000, 0, 0, 0, 0, 0], 1, MODERN_OPS + [QVEC(0, 1)])
pci_seed("modern_no_devcfg", pci_modern(dev_cap=False), [0x4000, 0, 0, 0, 0, 0], 0, MODERN_OPS)
pci_seed("modern_per_vq_notify", pci_modern(notify_len=0x2000), [0x4000, 0, 0, 0, 0, 0], 0, MODERN_OPS)
pci_seed("modern_reset", pci_modern(), [0x4000, 0, 0, 0, 0, 0], 0,
         [POKE(0, 18, 1), POKE(0, 24, 4), STAT(0), STAT(1, 3), SETF(V1 | (1 << 29)), FINDQ(1), KICK(0, 8), DELQ, FINDQ(1)])
pci_seed("modern_bridge_hdr", pci_modern(hdr_type=1), [0x4000, 0, 0, 0, 0, 0], 0, MODERN_OPS)
legacy = bytearray(256)
legacy[0x10] = 1  # BAR0 is an I/O-port BAR
pci_seed("legacy_basic", legacy, [0x100, 0, 0, 0, 0, 0], 0,
         [POKE(0, 12, 8), FINDQ(1), KICK(0, 64), GETB(0), GETC(0, 4), GETC(4, 1), SETC(0, 2), STAT(2), STAT(3), DELQ])


# --- vioinput_hid: 6 size bytes (EV_KEY, EV_REL, EV_ABS, EV_MSC, EV_LED, ABS_INFO), then the five bitmaps back to back ---
def bits(*codes):
    if not codes:
        return b""
    b = bytearray(max(codes) // 8 + 1)
    for c in codes:
        b[c // 8] |= 1 << (c % 8)
    return bytes(b)


def hid_seed(name, key=b"", rel=b"", ab=b"", msc=b"", led=b"", absinfo=20):
    sizes = bytes([len(key), len(rel), len(ab), len(msc), len(led), absinfo])
    w("vioinput_hid", name, sizes + key + rel + ab + msc + led + struct.pack("<5I", 0, 32767, 0, 0, 0))


KEYS_AZ = list(range(30, 39)) + list(range(16, 26)) + list(range(44, 51))
hid_seed("keyboard", key=bits(*KEYS_AZ, 28, 57), led=bits(0, 1, 2))
hid_seed("mouse", key=bits(0x110, 0x111, 0x112), rel=bits(0, 1, 8))
hid_seed("tablet", key=bits(0x14A), ab=bits(0, 1), msc=bits(5))
hid_seed("mouse_abs", key=bits(0x110, 0x111), ab=bits(0, 1))
hid_seed("joystick", key=bits(*range(0x120, 0x12A)), ab=bits(0, 1, 2, 5))
hid_seed("multitouch", key=bits(0x14A), ab=bits(0x2F, 0x35, 0x36, 0x39), msc=bits(5))
hid_seed("consumer", key=bits(113, 114, 115, 164, 165, 166))
hid_seed("keyboard_consumer", key=bits(*KEYS_AZ, 113, 114, 115), led=bits(0, 1))
hid_seed("empty")
hid_seed("rel_only", rel=bits(0, 1, 6, 8, 11))


# --- viogpu_edid: 128-byte base block (standard timings at 0x26, extension flag at 0x7e) + CTA-861 block ---
def edid(std=(), cta=None):
    b = bytearray(128)
    b[0:8] = bytes([0, 255, 255, 255, 255, 255, 255, 0])
    b[18], b[19] = 1, 4
    for i in range(8):
        a, r = std[i] if i < len(std) else (1, 1)
        b[0x26 + 2 * i], b[0x27 + 2 * i] = a, r << 6
    if cta is not None:
        b[0x7E] = 1
        c = bytearray(128)
        c[0], c[1], c[2] = 2, 3, 4 + 1 + len(cta)
        c[4:4 + len(cta)] = bytes(cta)
        return bytes(b) + bytes(c)
    return bytes(b)


w("viogpu_edid", "std_timings", edid(std=[(0x61, 1), (0x81, 0), (0x81, 2), (0xD1, 3), (0x45, 1)]))
w("viogpu_edid", "cta_vics", edid(cta=[16, 4, 31, 97, 63]))
w("viogpu_edid", "cta_vic_max", edid(cta=[127, 1, 100]))
w("viogpu_edid", "base_only", edid())
