/* A fake virtio PCI device behind VirtIOSystemOps: a 256-byte config space, six BARs of device-chosen
 * size, and plain-memory registers. Shared by the fuzz harness and the known-answer test. */
#pragma once
#include "osdep.h"
#include "virtio_pci.h"
#include "virtio.h"
#include "windows/virtio_ring_allocation.h"

#define FD_CFG_SIZE 256
#define FD_BARS     6

struct fakedev {
    uint8_t cfg[FD_CFG_SIZE];
    uint8_t *bar[FD_BARS];
    size_t barlen[FD_BARS];
    int msix;
    int mapped;
};

static struct fakedev g_fd;

static void fd_reset(void)
{
    int i;
    for (i = 0; i < FD_BARS; i++) {
        free(g_fd.bar[i]);
    }
    memset(&g_fd, 0, sizeof(g_fd));
}

/* A BAR whose config-space dword has bit 0 set is an I/O-port BAR (PCI spec: at most 256 bytes). The
 * driver's register accessors (VirtIO/WDF/MemPortIO.c) treat any address below 64K as a port, so port
 * BARs live at small fake port numbers and a stray port access is harmless on hardware. */
#define FD_PORT_BASE(bar) (0x1000u + (unsigned)(bar) * 0x100u)
#define FD_PORT_LIMIT     0x10000u

static int fd_is_port(int bar)
{
    return g_fd.cfg[0x10 + 4 * bar] & 1;
}

static void fd_set_bar(int bar, size_t len)
{
    free(g_fd.bar[bar]);
    if (fd_is_port(bar) && len > 0x100) {
        len = 0x100;
    }
    g_fd.bar[bar] = len ? (uint8_t *)calloc(1, len) : NULL;
    g_fd.barlen[bar] = len;
}

/* PCIe-style: bytes past the 256-byte legacy window read as zero, so a read never fails. */
static int fd_cfg_read(int where, void *out, size_t n)
{
    uint8_t tmp[4] = { 0, 0, 0, 0 };
    size_t i;
    for (i = 0; i < n; i++) {
        size_t at = (size_t)where + i;
        tmp[i] = at < FD_CFG_SIZE ? g_fd.cfg[at] : 0;
    }
    memcpy(out, tmp, n);
    return 0;
}

static int fd_read_byte(void *c, int w, u8 *v) { (void)c; return fd_cfg_read(w, v, 1); }
static int fd_read_word(void *c, int w, u16 *v) { (void)c; return fd_cfg_read(w, v, 2); }
static int fd_read_dword(void *c, int w, u32 *v) { (void)c; return fd_cfg_read(w, v, 4); }

static size_t fd_resource_len(void *c, int bar)
{
    (void)c;
    return (bar >= 0 && bar < FD_BARS) ? g_fd.barlen[bar] : 0;
}

/* Same contract as VirtIO/WDF/Callbacks.c pci_map_address_range: the start must be inside the BAR, the
 * length is not checked. The BAR is a heap block of exactly its size, so a driver access past it is an
 * ASan report. */
static void *fd_map_range(void *c, int bar, size_t offset, size_t maxlen)
{
    (void)c;
    (void)maxlen;
    if (bar < 0 || bar >= FD_BARS || !g_fd.bar[bar] || offset >= g_fd.barlen[bar]) {
        return NULL;
    }
    if (fd_is_port(bar)) {
        return (void *)(uintptr_t)(FD_PORT_BASE(bar) + offset);
    }
    g_fd.mapped = 1;
    return g_fd.bar[bar] + offset;
}

/* Register access: addresses >= 64K are memory-mapped BAR memory (a driver access past the BAR end is an
 * ASan report); below 64K they are ports, backed by the port BAR's bytes, with absent ports reading 0xFF
 * and ignoring writes. */
static uint8_t *fd_port_byte(ULONG_PTR a)
{
    int bar;
    for (bar = 0; bar < FD_BARS; bar++) {
        if (g_fd.bar[bar] && fd_is_port(bar) && a >= FD_PORT_BASE(bar) && a < FD_PORT_BASE(bar) + g_fd.barlen[bar]) {
            return g_fd.bar[bar] + (a - FD_PORT_BASE(bar));
        }
    }
    return NULL;
}

static uint32_t fd_rd(ULONG_PTR a, size_t n)
{
    uint8_t b[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint32_t v;
    size_t i;
    if (a >= FD_PORT_LIMIT) {
        memset(b, 0, sizeof(b));
        if (g_fd.mapped) {
            memcpy(b, (void *)a, n);
        }
    } else {
        for (i = 0; i < n; i++) {
            uint8_t *p = fd_port_byte(a + i);
            if (p) {
                b[i] = *p;
            }
        }
    }
    memcpy(&v, b, 4);
    return v;
}

static void fd_wr(ULONG_PTR a, uint32_t v, size_t n)
{
    size_t i;
    if (a >= FD_PORT_LIMIT) {
        if (g_fd.mapped) {
            memcpy((void *)a, &v, n);
        }
        return;
    }
    for (i = 0; i < n; i++) {
        uint8_t *p = fd_port_byte(a + i);
        if (p) {
            *p = (uint8_t)(v >> (8 * i));
        }
    }
}

static u8 fd_rd8(ULONG_PTR a) { return (u8)fd_rd(a, 1); }
static u16 fd_rd16(ULONG_PTR a) { return (u16)fd_rd(a, 2); }
static u32 fd_rd32(ULONG_PTR a) { return fd_rd(a, 4); }
static void fd_wr8(ULONG_PTR a, u8 v) { fd_wr(a, v, 1); }
static void fd_wr16(ULONG_PTR a, u16 v) { fd_wr(a, v, 2); }
static void fd_wr32(ULONG_PTR a, u32 v) { fd_wr(a, v, 4); }

static void *fd_alloc_pages(void *c, size_t size)
{
    void *p = NULL;
    (void)c;
    if (posix_memalign(&p, PAGE_SIZE, ROUND_TO_PAGES(size)) != 0) {
        return NULL;
    }
    memset(p, 0, ROUND_TO_PAGES(size));
    return p;
}
static void fd_free_pages(void *c, void *p) { (void)c; free(p); }
static ULONGLONG fd_phys(void *c, void *p) { (void)c; return (ULONGLONG)(uintptr_t)p; }
static void *fd_alloc_block(void *c, size_t size) { (void)c; return calloc(1, size ? size : 1); }
static void fd_free_block(void *c, void *p) { (void)c; free(p); }

static u16 fd_msix_vector(void *c, int queue)
{
    (void)c;
    return g_fd.msix ? (u16)(queue < 0 ? 0 : queue + 1) : VIRTIO_MSI_NO_VECTOR;
}
static void fd_sleep(void *c, unsigned int ms) { (void)c; (void)ms; }

static const VirtIOSystemOps fd_ops = {
    .vdev_read_byte = fd_rd8,
    .vdev_read_word = fd_rd16,
    .vdev_read_dword = fd_rd32,
    .vdev_write_byte = fd_wr8,
    .vdev_write_word = fd_wr16,
    .vdev_write_dword = fd_wr32,
    .mem_alloc_contiguous_pages = fd_alloc_pages,
    .mem_free_contiguous_pages = fd_free_pages,
    .mem_get_physical_address = fd_phys,
    .mem_alloc_nonpaged_block = fd_alloc_block,
    .mem_free_nonpaged_block = fd_free_block,
    .pci_read_config_byte = fd_read_byte,
    .pci_read_config_word = fd_read_word,
    .pci_read_config_dword = fd_read_dword,
    .pci_get_resource_len = fd_resource_len,
    .pci_map_address_range = fd_map_range,
    .vdev_get_msix_vector = fd_msix_vector,
    .vdev_sleep = fd_sleep,
};
