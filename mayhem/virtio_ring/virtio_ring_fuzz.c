/* libFuzzer harness for the guest side of VirtIO/VirtIORing.c (split) and VirtIORing-Packed.c (packed).
 * The input is a script: a queue configuration byte, then operations that either drive the driver API
 * (add/get/kick/enable_cb/...) or play the device writing into the shared ring memory. A "compliant"
 * device completion plus raw pokes let the fuzzer reach both valid state transitions and hostile
 * device-controlled ring contents. */
#include "osdep.h"
#include "virtio_pci.h"
#include "virtio.h"
#include "windows/virtio_ring_allocation.h"

#define MAX_TRACKED 4096
#define MAX_SG      16

void mayhem_bugcheck(unsigned int code)
{
    (void)code;
    abort();
}

/* defined in VirtIOPCICommon.c upstream; the notification itself is a device doorbell write. */
void virtqueue_notify(struct virtqueue *vq)
{
    (void)vq;
}

struct reader {
    const uint8_t *p;
    size_t n;
    size_t i;
};

static uint8_t rd8(struct reader *r)
{
    return r->i < r->n ? r->p[r->i++] : 0;
}

static uint16_t rd16(struct reader *r)
{
    uint16_t lo = rd8(r);
    return (uint16_t)(lo | ((uint16_t)rd8(r) << 8));
}

static uint32_t rd32(struct reader *r)
{
    uint32_t lo = rd16(r);
    return lo | ((uint32_t)rd16(r) << 16);
}

struct token {
    void *indirect;
};

struct state {
    struct virtqueue *vq;
    uint8_t *ring;
    unsigned num;
    unsigned align;
    int packed;
    /* device-side model */
    uint16_t dev_avail_idx;
    uint16_t dev_used_idx;
    uint16_t dev_pk_idx;
    int dev_pk_wrap;
    void *tracked[MAX_TRACKED];
    unsigned ntracked;
};

static void track(struct state *s, void *p)
{
    if (s->ntracked < MAX_TRACKED) {
        s->tracked[s->ntracked++] = p;
    }
}

static uint16_t ld16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static void st16(uint8_t *p, uint16_t v)
{
    memcpy(p, &v, 2);
}

static void st32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, 4);
}

static void op_add(struct state *s, struct reader *r)
{
    struct scatterlist sg[MAX_SG];
    uint8_t cfg = rd8(r);
    unsigned out = cfg & 7;
    unsigned in = (cfg >> 3) & 7;
    int indirect = (cfg >> 6) & 1;
    struct token *t;
    unsigned i;

    if (out + in == 0) {
        in = 1;
    }
    for (i = 0; i < out + in; i++) {
        sg[i].physAddr.QuadPart = (LONGLONG)(0x10000u + 0x1000u * i);
        sg[i].length = 1 + (rd16(r) & 0x1FFF);
    }
    t = (struct token *)calloc(1, sizeof(*t));
    track(s, t);
    if (indirect) {
        t->indirect = calloc(1, virtio_get_indirect_page_capacity() * 16);
        track(s, t->indirect);
    }
    (void)virtqueue_add_buf(s->vq, sg, out, in, t, t->indirect, t->indirect ? 0x20000 : 0);
}

static void op_dev_complete(struct state *s, struct reader *r)
{
    uint32_t len = rd32(r);
    uint8_t *e;

    if (!s->packed) {
        uint8_t *avail = (uint8_t *)s->vq->avail_va;
        uint8_t *used = (uint8_t *)s->vq->used_va;
        if (s->dev_avail_idx == ld16(avail + 2)) {
            return;
        }
        uint16_t id = ld16(avail + 4 + 2 * (s->dev_avail_idx & (s->num - 1)));
        e = used + 4 + 8 * (s->dev_used_idx & (s->num - 1));
        st32(e, id);
        st32(e + 4, len);
        s->dev_avail_idx++;
        s->dev_used_idx++;
        st16(used + 2, s->dev_used_idx);
    } else {
        uint8_t *d = s->ring + 16 * (size_t)s->dev_pk_idx;
        uint16_t first = ld16(d + 14);
        int avail_bit = (first >> 7) & 1;
        int used_bit = (first >> 15) & 1;
        unsigned chain = 1;
        uint16_t i = s->dev_pk_idx;
        uint16_t f = first;
        uint16_t wrapbits = s->dev_pk_wrap ? (uint16_t)((1u << 7) | (1u << 15)) : 0;

        if (avail_bit != s->dev_pk_wrap || used_bit == s->dev_pk_wrap) {
            return;
        }
        while (!(first & 4) && (f & 1) && chain < s->num) {
            chain++;
            i = (uint16_t)((i + 1) % s->num);
            f = ld16(s->ring + 16 * (size_t)i + 14);
        }
        st32(d + 8, len);
        st16(d + 14, (uint16_t)((first & ~((1u << 7) | (1u << 15))) | wrapbits));
        s->dev_pk_idx = (uint16_t)(s->dev_pk_idx + chain);
        if (s->dev_pk_idx >= s->num) {
            s->dev_pk_idx = (uint16_t)(s->dev_pk_idx - s->num);
            s->dev_pk_wrap ^= 1;
        }
    }
}

static void op_dev_raw_used(struct state *s, struct reader *r)
{
    uint32_t id = rd32(r);
    uint32_t len = rd32(r);
    if (!s->packed) {
        uint8_t *used = (uint8_t *)s->vq->used_va;
        uint8_t *e = used + 4 + 8 * (s->dev_used_idx & (s->num - 1));
        st32(e, id);
        st32(e + 4, len);
        s->dev_used_idx++;
        st16(used + 2, s->dev_used_idx);
    }
}

/* A raw device-side write. Only memory a device may write is poked: the split used ring (flags, idx,
 * entries, avail_event), and in packed mode the `len` of a descriptor plus the device event suppression
 * area. The descriptor table, avail ring, free-list `next` links and the packed id/flags are written only by
 * the driver (or by op_dev_complete, which models a compliant completion); poking them would corrupt
 * driver-owned state rather than model a hostile device. */
static void op_poke(struct state *s, struct reader *r)
{
    uint16_t sel = rd16(r);
    uint8_t v = rd8(r);
    size_t off;

    if (!s->packed) {
        size_t used_off = (size_t)((uint8_t *)s->vq->used_va - s->ring);
        size_t used_size = vring_size(s->num, s->align, false) - used_off;
        off = used_off + sel % used_size;
    } else {
        size_t dev_event_off = (size_t)((uint8_t *)s->vq->used_va - s->ring);
        size_t slot = (size_t)(sel >> 2) % ((size_t)s->num + 1);
        if (slot == s->num) {
            off = dev_event_off + (sel & 3);
        } else {
            off = 16 * slot + 8 + (sel & 3);
        }
    }
    s->ring[off] = v;
}

static void op_get(struct state *s)
{
    unsigned len = 0;
    (void)virtqueue_get_buf(s->vq, &len);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct reader r = {data, size, 0};
    struct state s;
    VirtIODevice vdev;
    uint8_t cfg;
    unsigned ops = 0;
    size_t ring_size, ctl_size;
    void *ctl;
    unsigned i;
    void *pages = NULL;

    if (size < 2) {
        return -1;
    }
    memset(&s, 0, sizeof(s));
    memset(&vdev, 0, sizeof(vdev));
    cfg = rd8(&r);
    s.packed = cfg & 1;
    vdev.event_suppression_enabled = (cfg >> 1) & 1;
    vdev.packed_ring = (bool)s.packed;
    vdev.addr = (cfg >> 2) & 1 ? 0x1000 : 0;
    s.align = vdev.addr ? PAGE_SIZE : SMP_CACHE_BYTES;
    s.num = 1u << (1 + ((cfg >> 3) & 7));
    s.dev_pk_wrap = 1;

    ring_size = vring_size(s.num, s.align, (bool)s.packed);
    ctl_size = vring_control_block_size((u16)s.num, (bool)s.packed);
    if (posix_memalign(&pages, 4096, ring_size) != 0) {
        return 0;
    }
    ctl = malloc(ctl_size);
    memset(pages, 0, ring_size);
    s.ring = (uint8_t *)pages;
    s.vq = s.packed ? vring_new_virtqueue_packed(0, s.num, s.align, &vdev, pages, NULL, ctl) :
                      vring_new_virtqueue_split(0, s.num, s.align, &vdev, pages, NULL, ctl);
    if (s.vq == NULL) {
        goto out;
    }

    while (r.i < r.n && ops++ < 512) {
        switch (rd8(&r) % 14) {
        case 0:
        case 1:
        case 2:
            op_add(&s, &r);
            break;
        case 3:
        case 4:
            op_dev_complete(&s, &r);
            break;
        case 5:
        case 6:
            op_get(&s);
            break;
        case 7:
            (void)virtqueue_has_buf(s.vq);
            (void)virtqueue_is_interrupt_enabled(s.vq);
            break;
        case 8:
            (void)virtqueue_kick_prepare(s.vq);
            break;
        case 9:
            virtqueue_kick_always(s.vq);
            break;
        case 10:
            if (rd8(&r) & 1) {
                (void)virtqueue_enable_cb(s.vq);
            } else {
                (void)virtqueue_enable_cb_delayed(s.vq);
            }
            break;
        case 11:
            virtqueue_disable_cb(s.vq);
            break;
        case 12:
            if (rd8(&r) & 1) {
                op_dev_raw_used(&s, &r);
            } else {
                op_poke(&s, &r);
            }
            break;
        case 13:
            if (rd8(&r) & 1) {
                /* detach_unused_buf is only valid on a stopped device: callers drain it in a loop
                 * after a device reset (viosock, vioserial). Model that: drain, then re-initialize
                 * the ring and the device-side view of it. */
                while (virtqueue_detach_unused_buf(s.vq) != NULL) {
                }
            }
            virtqueue_shutdown(s.vq);
            s.dev_avail_idx = s.dev_used_idx = s.dev_pk_idx = 0;
            s.dev_pk_wrap = 1;
            break;
        }
    }

out:
    for (i = 0; i < s.ntracked; i++) {
        free(s.tracked[i]);
    }
    free(ctl);
    free(pages);
    return 0;
}
