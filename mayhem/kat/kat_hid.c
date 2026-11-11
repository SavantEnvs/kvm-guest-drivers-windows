// Known-answer test for vioinput's HID report-descriptor builder: well-formed virtio-input devices in, report
// descriptors (length, class count, leading bytes) out.
#include "../vioinput_hid/fakecfg.h"

struct dev
{
    uint8_t key[64], rel[8], abs[16], msc[8], led[4];
};

static void set(uint8_t *bm, int code) { bm[code / 8] |= (uint8_t)(1 << (code % 8)); }

static void run(const char *name, const struct dev *d, int nk, int nr, int na, int nm, int nl)
{
    uint8_t blob[256], *p = blob;
    *p++ = (uint8_t)nk, *p++ = (uint8_t)nr, *p++ = (uint8_t)na, *p++ = (uint8_t)nm, *p++ = (uint8_t)nl, *p++ = 20;
    memcpy(p, d->key, nk), p += nk;
    memcpy(p, d->rel, nr), p += nr;
    memcpy(p, d->abs, na), p += na;
    memcpy(p, d->msc, nm), p += nm;
    memcpy(p, d->led, nl), p += nl;
    memset(p, 0, 20);
    p[4] = 0xff, p[5] = 0x7f; /* an abs axis range of 0..32767 */
    INPUT_DEVICE *ctx = fake_build(blob, (size_t)(p + 20 - blob));
    printf("%s: classes=%u len=%u bytes=", name, ctx->uNumOfClasses, ctx->HidDescriptor.DescriptorList[0].wReportLength);
    for (unsigned i = 0; ctx->HidReportDescriptor && i < ctx->HidDescriptor.DescriptorList[0].wReportLength && i < 16; i++)
        printf("%02x", ctx->HidReportDescriptor[i]);
    printf("\n");
    fake_free(ctx);
}

int main(void)
{
    struct dev d;

    memset(&d, 0, sizeof(d));
    for (int c = 30; c <= 38; c++) set(d.key, c); /* KEY_A..KEY_I */
    set(d.key, 28), set(d.key, 57);               /* enter, space */
    set(d.led, 0), set(d.led, 1), set(d.led, 2);
    run("keyboard", &d, 8, 0, 0, 0, 1);

    memset(&d, 0, sizeof(d));
    set(d.key, 0x110), set(d.key, 0x111), set(d.key, 0x112);
    set(d.rel, 0), set(d.rel, 1), set(d.rel, 8);
    run("mouse", &d, 35, 2, 0, 0, 0);

    memset(&d, 0, sizeof(d));
    set(d.key, 0x14a);
    set(d.abs, 0), set(d.abs, 1);
    run("tablet", &d, 42, 0, 1, 0, 0);

    memset(&d, 0, sizeof(d));
    for (int c = 0x120; c < 0x12a; c++) set(d.key, c);
    set(d.abs, 0), set(d.abs, 1), set(d.abs, 2), set(d.abs, 5);
    run("joystick", &d, 38, 0, 1, 0, 0);

    memset(&d, 0, sizeof(d));
    set(d.key, 113), set(d.key, 114), set(d.key, 115);
    run("consumer", &d, 15, 0, 0, 0, 0);

    memset(&d, 0, sizeof(d));
    run("empty", &d, 0, 0, 0, 0, 0);
    return 0;
}
