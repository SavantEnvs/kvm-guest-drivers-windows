/* libFuzzer harness for the guest side of VirtIO/VirtIOPCICommon.c, VirtIOPCIModern.c and
 * VirtIOPCILegacy.c: PCI capability discovery, BAR mapping, device config access and virtqueue setup,
 * driven through virtio_device_initialize() against a hostile fake device (see fakedev.h).
 *
 * Input: 256 bytes of PCI config space, six little-endian u16 BAR sizes, one flag byte (bit0 = MSI-X in
 * use), then a script of driver calls interleaved with device-side writes into the BAR memory. */
#include "fakedev.h"

#define MAX_OPS    64
#define MAX_QUEUES 12

void mayhem_bugcheck(unsigned int code)
{
    (void)code;
    abort();
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

static uint64_t rd64(struct reader *r)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) {
        v |= (uint64_t)rd8(r) << (8 * i);
    }
    return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct reader r;
    VirtIODevice *vdev;
    struct virtqueue *vqs[MAX_QUEUES];
    unsigned nq = 0, ops = 0, i;
    NTSTATUS st;
    uint8_t buf[256];
    static int tok;

    if (size < FD_CFG_SIZE + 2 * FD_BARS + 1) {
        return -1;
    }
    fd_reset();
    memcpy(g_fd.cfg, data, FD_CFG_SIZE);
    r.p = data + FD_CFG_SIZE;
    r.n = size - FD_CFG_SIZE;
    r.i = 0;
    for (i = 0; i < FD_BARS; i++) {
        fd_set_bar((int)i, rd16(&r));
    }
    g_fd.msix = rd8(&r) & 1;

    vdev = (VirtIODevice *)calloc(1, sizeof(*vdev));
    st = virtio_device_initialize(vdev, &fd_ops, NULL, (bool)g_fd.msix);
    if (!NT_SUCCESS(st)) {
        goto out;
    }

    while (r.i < r.n && ops++ < MAX_OPS) {
        switch (rd8(&r) % 12) {
        case 0: { /* device writes a byte into a BAR */
            unsigned bar = rd8(&r) % FD_BARS;
            uint16_t off = rd16(&r);
            uint8_t v = rd8(&r);
            if (g_fd.bar[bar] && off < g_fd.barlen[bar]) {
                g_fd.bar[bar][off] = v;
            }
            break;
        }
        case 1: { /* device writes a 32-bit little-endian value into a BAR */
            unsigned bar = rd8(&r) % FD_BARS;
            uint16_t off = rd16(&r);
            uint32_t v = (uint32_t)rd16(&r) | ((uint32_t)rd16(&r) << 16);
            if (g_fd.bar[bar] && (size_t)off + 4 <= g_fd.barlen[bar]) {
                memcpy(g_fd.bar[bar] + off, &v, 4);
            }
            break;
        }
        case 2: {
            unsigned off = rd8(&r); /* callers pass the offset of a field in the device's config struct */
            unsigned len = rd8(&r) % 33;
            virtio_get_config(vdev, off, buf, len);
            break;
        }
        case 3: {
            unsigned off = rd8(&r);
            unsigned len = rd8(&r) % 33;
            memset(buf, 0xA5, sizeof(buf));
            virtio_set_config(vdev, off, buf, len);
            break;
        }
        case 4:
            if (nq == 0) {
                unsigned want = 1 + rd8(&r) % MAX_QUEUES;
                if (NT_SUCCESS(virtio_find_queues(vdev, want, vqs))) {
                    nq = want;
                }
            }
            break;
        case 5:
            virtio_delete_queues(vdev);
            nq = 0;
            break;
        case 6: {
            unsigned short n;
            unsigned long rs, hs;
            (void)virtio_query_queue_allocation(vdev, rd8(&r), &n, &rs, &hs);
            break;
        }
        case 7:
            if (rd8(&r) & 1) {
                (void)virtio_set_features(vdev, rd64(&r));
            } else {
                (void)virtio_get_features(vdev);
            }
            break;
        case 8:
            switch (rd8(&r) % 5) {
            case 0:
                virtio_device_reset(vdev);
                break;
            case 1:
                virtio_add_status(vdev, rd8(&r));
                break;
            case 2:
                (void)virtio_get_status(vdev);
                break;
            case 3:
                (void)virtio_read_isr_status(vdev);
                break;
            case 4:
                (void)virtio_set_config_vector(vdev, rd16(&r));
                break;
            }
            break;
        case 9:
            if (nq) {
                struct virtqueue *vq = vqs[rd8(&r) % nq];
                if (rd8(&r) & 1) {
                    (void)virtio_set_queue_vector(vq, rd16(&r));
                } else {
                    (void)virtio_get_queue_size(vq);
                }
            }
            break;
        case 10:
            if (nq) { /* post one buffer and ring the doorbell: writes through vq->notification_addr */
                struct virtqueue *vq = vqs[rd8(&r) % nq];
                struct scatterlist sg;
                sg.physAddr.QuadPart = 0x10000;
                sg.length = 1 + rd16(&r);
                if (virtqueue_add_buf(vq, &sg, 1, 0, &tok, NULL, 0) >= 0) {
                    virtqueue_kick(vq);
                }
            }
            break;
        case 11:
            if (nq) {
                unsigned len;
                struct virtqueue *vq = vqs[rd8(&r) % nq];
                (void)virtqueue_get_buf(vq, &len);
            }
            break;
        }
    }

    virtio_delete_queues(vdev);
out:
    virtio_device_shutdown(vdev);
    free(vdev);
    fd_reset();
    return 0;
}
