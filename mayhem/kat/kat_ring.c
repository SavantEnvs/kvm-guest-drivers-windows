/* Known-answer tests for VirtIO/VirtIORing.c (split) and VirtIORing-Packed.c (packed): ring sizes from
 * the virtio spec formulas, descriptor layout written by add_buf, and the add -> device completes ->
 * get_buf round trip. The device side is played here by writing the ring memory directly. */
#include "osdep.h"
#include "virtio_pci.h"
#include "virtio.h"
#include "windows/virtio_ring_allocation.h"

void mayhem_bugcheck(unsigned int code) { printf("BUGCHECK %x\n", code); exit(3); }
void virtqueue_notify(struct virtqueue *vq) { (void)vq; }

static uint16_t ld16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t ld32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t ld64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static void st16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void st32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static struct virtqueue *mkq(VirtIODevice *vdev, int packed, unsigned num, void **mem)
{
    size_t sz = vring_size(num, 4096, packed);
    void *pages = NULL, *ctl;
    posix_memalign(&pages, 4096, sz);
    memset(pages, 0, sz);
    ctl = malloc(vring_control_block_size((u16)num, packed));
    *mem = pages;
    return packed ? vring_new_virtqueue_packed(0, num, 4096, vdev, pages, NULL, ctl) :
                    vring_new_virtqueue_split(0, num, 4096, vdev, pages, NULL, ctl);
}

static void split_tests(void)
{
    VirtIODevice vdev;
    void *mem;
    struct virtqueue *vq;
    struct scatterlist sg[2];
    int tok1, tok2, i;
    unsigned len = 0;
    uint8_t *desc, *avail, *used;
    void *got;

    memset(&vdev, 0, sizeof(vdev));
    vdev.addr = 0x1000;
    vq = mkq(&vdev, 0, 8, &mem);
    desc = (uint8_t *)mem;
    avail = (uint8_t *)vq->avail_va;
    used = (uint8_t *)vq->used_va;
    printf("split.layout: avail_off=%ld used_off=%ld\n", (long)(avail - desc), (long)(used - desc));
    printf("split.size: n256=%lu n8=%lu\n", vring_size(256, 4096, 0), vring_size(8, 4096, 0));

    sg[0].physAddr.QuadPart = 0x1000; sg[0].length = 64;
    sg[1].physAddr.QuadPart = 0x2000; sg[1].length = 1500;
    printf("split.add2: rc=%d\n", virtqueue_add_buf(vq, sg, 1, 1, &tok1, NULL, 0));
    printf("split.desc0: addr=%llx len=%u flags=%u next=%u\n", (unsigned long long)ld64(desc), ld32(desc + 8),
           ld16(desc + 12), ld16(desc + 14));
    printf("split.desc1: addr=%llx len=%u flags=%u next=%u\n", (unsigned long long)ld64(desc + 16), ld32(desc + 24),
           ld16(desc + 28), ld16(desc + 30));
    printf("split.avail: idx=%u ring0=%u\n", ld16(avail + 2), ld16(avail + 4));
    printf("split.has_buf_before=%d kick_prepare=%d\n", virtqueue_has_buf(vq), virtqueue_kick_prepare(vq));

    st32(used + 4, 0);
    st32(used + 8, 1564);
    st16(used + 2, 1);
    printf("split.has_buf_after=%d\n", virtqueue_has_buf(vq));
    got = virtqueue_get_buf(vq, &len);
    printf("split.get_buf: opaque_ok=%d len=%u has_buf=%d\n", got == &tok1, len, virtqueue_has_buf(vq));

    for (i = 0; i < 8; i++) {
        sg[0].length = 100 + i;
        (void)virtqueue_add_buf(vq, sg, 1, 0, &tok2, NULL, 0);
    }
    printf("split.add_when_full: rc=%d\n", virtqueue_add_buf(vq, sg, 1, 0, &tok2, NULL, 0));
    got = virtqueue_detach_unused_buf(vq);
    printf("split.detach_unused: opaque_ok=%d avail_idx=%u\n", got == &tok2, ld16(avail + 2));

    printf("split.cb: interrupts_on=%d ", virtqueue_is_interrupt_enabled(vq));
    virtqueue_disable_cb(vq);
    printf("after_disable=%d ", virtqueue_is_interrupt_enabled(vq));
    printf("enable_cb_empty_rc=%d\n", virtqueue_enable_cb(vq));
    st16(used + 0, 1);
    printf("split.kick_prepare_no_notify=%d\n", virtqueue_kick_prepare(vq));
}

static void packed_tests(void)
{
    VirtIODevice vdev;
    void *mem;
    struct virtqueue *vq;
    struct scatterlist sg[2];
    int tok1, tok2, i;
    unsigned len = 0;
    uint8_t *desc;
    void *got;

    memset(&vdev, 0, sizeof(vdev));
    vdev.addr = 0x1000;
    vdev.packed_ring = 1;
    vq = mkq(&vdev, 1, 4, &mem);
    desc = (uint8_t *)mem;
    printf("packed.size: n256=%lu n4=%lu\n", vring_size(256, 4096, 1), vring_size(4, 4096, 1));

    sg[0].physAddr.QuadPart = 0x1000; sg[0].length = 64;
    sg[1].physAddr.QuadPart = 0x2000; sg[1].length = 1500;
    printf("packed.add2: rc=%d\n", virtqueue_add_buf(vq, sg, 1, 1, &tok1, NULL, 0));
    printf("packed.desc0: addr=%llx len=%u id=%u flags=%x\n", (unsigned long long)ld64(desc), ld32(desc + 8),
           ld16(desc + 12), ld16(desc + 14));
    printf("packed.desc1: addr=%llx len=%u id=%u flags=%x\n", (unsigned long long)ld64(desc + 16), ld32(desc + 24),
           ld16(desc + 28), ld16(desc + 30));
    printf("packed.has_buf_before=%d\n", virtqueue_get_buf(vq, &len) != NULL);

    st32(desc + 8, 777);
    st16(desc + 14, (uint16_t)((1u << 7) | (1u << 15)));
    got = virtqueue_get_buf(vq, &len);
    printf("packed.get_buf: opaque_ok=%d len=%u\n", got == &tok1, len);

    for (i = 0; i < 2; i++) {
        sg[0].length = 10 + i;
        (void)virtqueue_add_buf(vq, sg, 1, 0, &tok2, NULL, 0);
    }
    printf("packed.add_when_full: rc=%d\n", virtqueue_add_buf(vq, sg, 2, 1, &tok2, NULL, 0));
    got = virtqueue_detach_unused_buf(vq);
    printf("packed.detach_unused: opaque_ok=%d\n", got == &tok2);
}

int main(void)
{
    split_tests();
    packed_tests();
    return 0;
}
