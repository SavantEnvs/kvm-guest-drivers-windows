// Known-answer test for viogpu's EDID helpers: standard-timing descriptors and CTA-861 VIC codes in, resolutions out.
#include "edid.h"

static void std_timing(const char *name, UCHAR h, UCHAR ar)
{
    STANDARD_TIMING_DESCRIPTOR d{};
    d.HorizontalActivePixels = h;
    d.ImageAspectRatio = ar;
    VIOGPU_DISP_MODE m{0};
    bool ok = GetStandardTimingResolution(&d, &m);
    printf("std %s: ok=%d %ux%u\n", name, ok, m.XResolution, m.YResolution);
}

static void vic(USHORT idx)
{
    VIOGPU_DISP_MODE m{0};
    bool ok = GetVICResolution(idx, &m);
    printf("vic %u: ok=%d %ux%u\n", idx, ok, m.XResolution, m.YResolution);
}

int main()
{
    std_timing("1024x768", 0x61, AR_4_3);
    std_timing("1280x800", 0x81, AR_16_10);
    std_timing("1280x1024", 0x81, AR_5_4);
    std_timing("1920x1080", 0xD1, AR_16_9);
    std_timing("unused", 0x00, AR_4_3);
    vic(1);
    vic(4);
    vic(16);
    vic(127);
    vic(128);
    return 0;
}
