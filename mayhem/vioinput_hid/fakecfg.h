#pragma once
// Fuzzes vioinput's HID report-descriptor builder (VIOInputBuildReportDescriptor and the HID*Probe functions) against a
// virtio-input device whose config space is entirely attacker-controlled. VirtIOWdfDeviceGet/Set (a one-line forward to
// virtio_get_config/set_config in the real driver) are replaced by a fake config space driven by the input bytes.
#include "precomp.h"
#include "vioinput.h"

// The WDF I/O entry points only the IOCTL/report paths use; the descriptor builder never reaches them.
WDFDEVICE WdfIoQueueGetDevice(WDFQUEUE q) { abort(); }
void WdfRequestComplete(WDFREQUEST r, NTSTATUS s) { abort(); }
PIRP WdfRequestWdmGetIrp(WDFREQUEST r) { abort(); }
void WdfRequestSetInformation(WDFREQUEST r, ULONG_PTR i) { abort(); }
void WdfRequestGetParameters(WDFREQUEST r, WDF_REQUEST_PARAMETERS *p) { abort(); }
NTSTATUS WdfRequestRetrieveOutputMemory(WDFREQUEST r, WDFMEMORY *m) { abort(); }
NTSTATUS WdfRequestForwardToIoQueue(WDFREQUEST r, WDFQUEUE q) { abort(); }
NTSTATUS WdfIoQueueRetrieveNextRequest(WDFQUEUE q, WDFREQUEST *r) { abort(); }
PVOID WdfMemoryGetBuffer(WDFMEMORY m, size_t *n) { abort(); }
NTSTATUS WdfMemoryCopyFromBuffer(WDFMEMORY m, size_t o, PVOID b, size_t n) { abort(); }
NTSTATUS VIOInputAddOutBuf(struct virtqueue *vq, PVIRTIO_INPUT_EVENT buf, PHYSICAL_ADDRESS pa) { abort(); }
void WdfSpinLockAcquire(WDFSPINLOCK l) { abort(); }
void WdfSpinLockRelease(WDFSPINLOCK l) { abort(); }

static const uint8_t *g_in;
static size_t g_n;
static uint8_t g_sel, g_sub;
static uint8_t g_size[6]; // sizes reported for EV_KEY, EV_REL, EV_ABS, EV_MSC, EV_LED, ABS_INFO
static size_t g_off[5];

static int ev_index(void)
{
    if (g_sel != VIRTIO_INPUT_CFG_EV_BITS)
        return -1;
    switch (g_sub)
    {
        case EV_KEY: return 0;
        case EV_REL: return 1;
        case EV_ABS: return 2;
        case EV_MSC: return 3;
        case EV_LED: return 4;
    }
    return -1;
}

static uint8_t cfg_size(void)
{
    int k = ev_index();
    if (k >= 0)
        return g_size[k];
    return g_sel == VIRTIO_INPUT_CFG_ABS_INFO ? g_size[5] : 0;
}

static uint8_t cfg_byte(ULONG idx)
{
    int k = ev_index();
    if (k >= 0)
    {
        size_t pos = g_off[k] + idx;
        return (idx < g_size[k] && pos < g_n) ? g_in[pos] : 0;
    }
    if (g_sel == VIRTIO_INPUT_CFG_ABS_INFO && idx < g_size[5])
        return g_in[(g_sub * 3u + idx) % g_n];
    return 0;
}

void VirtIOWdfDeviceGet(PVIRTIO_WDF_DRIVER pWdfDriver, ULONG offset, PVOID buf, ULONG len)
{
    uint8_t *out = buf;
    for (ULONG k = 0; k < len; k++)
    {
        ULONG a = offset + k;
        out[k] = a == offsetof(struct virtio_input_config, size) ? cfg_size()
                 : a >= offsetof(struct virtio_input_config, u)  ? cfg_byte(a - offsetof(struct virtio_input_config, u))
                                                                 : 0;
    }
}

void VirtIOWdfDeviceSet(PVIRTIO_WDF_DRIVER pWdfDriver, ULONG offset, CONST PVOID buf, ULONG len)
{
    if (len == 1 && offset == offsetof(struct virtio_input_config, select))
        g_sel = *(const uint8_t *)buf;
    else if (len == 1 && offset == offsetof(struct virtio_input_config, subsel))
        g_sub = *(const uint8_t *)buf;
}


// Builds the HID descriptor for the fake device described by `data` (6 size bytes, then the bitmaps); caller frees with fake_free.
static INPUT_DEVICE *fake_build(const uint8_t *data, size_t size)
{
    static INPUT_DEVICE ctx;
    g_in = data;
    g_n = size;
    g_sel = g_sub = 0;
    memcpy(g_size, data, sizeof(g_size));
    size_t pos = sizeof(g_size);
    for (int k = 0; k < 5; k++)
    {
        g_off[k] = pos;
        pos += g_size[k];
    }
    memset(&ctx, 0, sizeof(ctx));
    VIOInputBuildReportDescriptor(&ctx);
    return &ctx;
}

static void fake_free(INPUT_DEVICE *ctx)
{
    for (ULONG i = 0; i < ctx->uNumOfClasses; i++)
    {
        PINPUT_CLASS_COMMON pClass = ctx->InputClasses[i];
        if (pClass->CleanupFunc)
            pClass->CleanupFunc(pClass);
        VIOInputFree(&pClass->pHidReport);
        VIOInputFree(&pClass);
    }
    VIOInputFree(&ctx->HidReportDescriptor);
}
