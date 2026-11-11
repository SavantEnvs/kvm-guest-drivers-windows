#include "fakecfg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < sizeof(g_size))
        return -1;
    fake_free(fake_build(data, size));
    return 0;
}
