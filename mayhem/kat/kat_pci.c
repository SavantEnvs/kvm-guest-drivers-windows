/* Known-answer tests for VirtIO/VirtIOPCIModern.c (capability walk, BAR mapping, queue setup) and the
 * VirtIOPCICommon.c / VirtIOPCILegacy.c entry points, against the fake device in
 * mayhem/virtio_pci/fakedev.h. */
#include "../virtio_pci/fakedev.h"

void mayhem_bugcheck(unsigned int code) { printf("BUGCHECK %x\n", code); exit(3); }

static void put_cap(int at, int next, int type, int bar, uint32_t off, uint32_t len)
{
    uint8_t *c = g_fd.cfg + at;
    memset(c, 0, 16);
    c[0] = 9; c[1] = (uint8_t)next; c[2] = 16; c[3] = (uint8_t)type; c[4] = (uint8_t)bar;
    memcpy(c + 8, &off, 4);
    memcpy(c + 12, &len, 4);
}

static void modern_layout(uint32_t common_off, int with_isr)
{
    fd_reset();
    g_fd.cfg[0x06] = 0x10;
    g_fd.cfg[0x34] = 0x40;
    put_cap(0x40, 0x50, 1, 0, common_off, 56);
    put_cap(0x50, 0x64, 2, 0, 0x1000, 0x400);
    memcpy(g_fd.cfg + 0x60, (uint32_t[]){ 4 }, 4);          /* notify_off_multiplier */
    g_fd.cfg[0x50 + 2] = 20;
    put_cap(0x64, with_isr ? 0x74 : 0, with_isr ? 3 : 4, 0, with_isr ? 0x2000 : 0x3000, with_isr ? 1 : 0x100);
    if (with_isr) {
        put_cap(0x74, 0, 4, 0, 0x3000, 0x100);
    }
    fd_set_bar(0, 0x4000);
}

static void report_init(const char *name, VirtIODevice *vdev, NTSTATUS st)
{
    printf("%s: status=0x%x\n", name, (unsigned)st);
    if (st == STATUS_SUCCESS && vdev->common) {
        uint8_t *b = g_fd.bar[0];
        printf("%s.map: common=%ld isr=%ld notify=%ld notify_len=%zu config=%ld config_len=%zu mult=%u\n", name,
               (long)((uint8_t *)vdev->common - b), (long)((uint8_t *)vdev->isr - b),
               (long)((uint8_t *)vdev->notify_base - b), vdev->notify_len, (long)((uint8_t *)vdev->config - b),
               vdev->config_len, vdev->notify_offset_multiplier);
    }
}

int main(void)
{
    VirtIODevice *vdev = (VirtIODevice *)calloc(1, sizeof(*vdev));
    struct virtqueue *vqs[2];
    NTSTATUS st;
    uint8_t cfgbuf[8] = { 0 };
    uint32_t v32 = 0;
    unsigned short n;
    unsigned long rs, hs;

    modern_layout(0, 1);
    st = virtio_device_initialize(vdev, &fd_ops, NULL, 0);
    report_init("modern", vdev, st);
    printf("modern.status_after_init=%u\n", virtio_get_status(vdev));
    g_fd.bar[0][18] = 2;                                      /* num_queues */
    g_fd.bar[0][24] = 8;                                      /* queue_size */
    memcpy(g_fd.bar[0] + 0x3000, "\x11\x22\x33\x44\x55\x66\x77\x88", 8);
    virtio_get_config(vdev, 0, cfgbuf, 1);
    printf("modern.cfg1=%02x\n", cfgbuf[0]);
    virtio_get_config(vdev, 4, &v32, 4);
    printf("modern.cfg4=%08x\n", v32);
    virtio_get_config(vdev, 0x100, cfgbuf, 1);                /* beyond config_len: ignored */
    printf("modern.cfg_oob=%02x\n", cfgbuf[0]);
    memset(cfgbuf, 0xEE, sizeof(cfgbuf));
    virtio_set_config(vdev, 2, cfgbuf, 2);
    printf("modern.set_cfg2=%02x%02x%02x%02x\n", g_fd.bar[0][0x3000 + 1], g_fd.bar[0][0x3000 + 2], g_fd.bar[0][0x3000 + 3],
           g_fd.bar[0][0x3000 + 4]);
    printf("modern.set_features=0x%x\n", (unsigned)virtio_set_features(vdev, (uint64_t)1 << 32));
    printf("modern.status_after_features=%u\n", virtio_get_status(vdev));
    st = virtio_query_queue_allocation(vdev, 1, &n, &rs, &hs);
    printf("modern.query1: status=0x%x num=%u ring=%lu heap_nonzero=%d\n", (unsigned)st, n, rs, hs > 0);
    st = virtio_query_queue_allocation(vdev, 2, &n, &rs, &hs);
    printf("modern.query2: status=0x%x\n", (unsigned)st);
    st = virtio_find_queues(vdev, 2, vqs);
    printf("modern.find_queues: status=0x%x notify_addr0=%ld size0=%u\n", (unsigned)st,
           (long)((uint8_t *)vqs[0]->notification_addr - g_fd.bar[0]), virtio_get_queue_size(vqs[0]));
    {
        struct scatterlist sg;
        int tok;
        sg.physAddr.QuadPart = 0x10000;
        sg.length = 100;
        printf("modern.add_buf=%d\n", virtqueue_add_buf(vqs[1], &sg, 1, 0, &tok, NULL, 0));
        virtqueue_kick(vqs[1]);
        printf("modern.kick_wrote=%u\n", (unsigned)(g_fd.bar[0][0x1000] | (g_fd.bar[0][0x1001] << 8)));
    }
    virtio_delete_queues(vdev);
    virtio_device_shutdown(vdev);

    modern_layout(0, 0);
    st = virtio_device_initialize(vdev, &fd_ops, NULL, 0);
    printf("no_isr: status=0x%x\n", (unsigned)st);
    modern_layout(2, 1);
    st = virtio_device_initialize(vdev, &fd_ops, NULL, 0);
    printf("misaligned_common: status=0x%x\n", (unsigned)st);
    modern_layout(0x3FF0, 1);
    st = virtio_device_initialize(vdev, &fd_ops, NULL, 0);
    printf("common_past_bar: status=0x%x\n", (unsigned)st);

    fd_reset();
    g_fd.cfg[0x10] = 1;
    fd_set_bar(0, 0x100);
    g_fd.bar[0][12] = 16;                                     /* QUEUE_NUM */
    st = virtio_device_initialize(vdev, &fd_ops, NULL, 0);
    printf("legacy: status=0x%x addr_set=%d\n", (unsigned)st, vdev->addr != 0);
    st = virtio_query_queue_allocation(vdev, 0, &n, &rs, &hs);
    printf("legacy.query0: status=0x%x num=%u\n", (unsigned)st, n);
    printf("legacy.status_after_init=%u\n", virtio_get_status(vdev));
    fd_reset();
    free(vdev);
    return 0;
}
