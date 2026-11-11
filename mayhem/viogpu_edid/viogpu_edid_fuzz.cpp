// Fuzzes viogpu's EDID mode extraction. The EDID the host hands the guest (a 128-byte base block plus an optional CTA-861
// extension, in a 256-byte buffer like VioGpuAdapter::m_EDIDs) is walked the way VioGpuAdapter::AddEdidModes /
// GetCTA861Data walk it (that class is tied to the WDDM miniport, so the two loops are mirrored here), and every standard
// timing and CTA video-identification code goes through the real GetStandardTimingResolution / GetVICResolution.
#include "edid.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return -1;
    UCHAR *edids = (UCHAR *)malloc(EDID_RAW_BLOCK_SIZE);
    memset(edids, 0, EDID_RAW_BLOCK_SIZE);
    memcpy(edids, data, size < EDID_RAW_BLOCK_SIZE ? size : EDID_RAW_BLOCK_SIZE);

    volatile unsigned sink = 0;
    PEDID_DATA_V1 edid_data = (PEDID_DATA_V1)edids;
    PSTANDARD_TIMING_DESCRIPTOR standard_timing = edid_data->StandardTimings;
    for (int i = 0; i < 8; i++, standard_timing++)
    {
        VIOGPU_DISP_MODE mode{0};
        if (GetStandardTimingResolution(standard_timing, &mode))
            sink += mode.XResolution + mode.YResolution;
    }

    PEDID_CTA_861 cta_data = NULL;
    if (edid_data->ExtensionFlag[0])
    {
        PEDID_CTA_861 cta = (PEDID_CTA_861)(edids + EDID_V1_BLOCK_SIZE);
        if (cta->ExtentionTag[0] >= 2 && cta->Revision[0] >= 3)
            cta_data = cta;
    }
    if (cta_data && cta_data->DTDBegin[0] > 4)
    {
        int vics = (cta_data->DTDBegin[0] - 1) - 4;
        for (int idx = 0; idx < vics; idx++)
        {
            VIOGPU_DISP_MODE mode{0};
            USHORT vic_num = cta_data->Data[idx];
            if (GetVICResolution(vic_num, &mode))
                sink += mode.XResolution + mode.YResolution;
        }
    }
    free(edids);
    return 0;
}
