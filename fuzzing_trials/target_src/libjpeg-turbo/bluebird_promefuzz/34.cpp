#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "../src/turbojpeg.h"
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Set up a TurboJPEG instance
    tjhandle handle = tj3Init(TJINIT_TRANSFORM);
    if (!handle) {
        fprintf(stderr, "Failed to initialize TurboJPEG instance\n");
        return 0;
    }

    // Prepare transformation structures
    tjtransform transform;
    memset(&transform, 0, sizeof(tjtransform));

    // Create dummy destination buffers
    unsigned char *dstBufs[1] = {nullptr};
    size_t dstSizes[1] = {0};

    // Attempt to transform the input data
    int transformResult = tj3Transform(handle, Data, Size, 1, dstBufs, dstSizes, &transform);

    // Check for errors
    if (transformResult != 0) {
        char *errorStr = tj3GetErrorStr(handle);
        if (errorStr) {
            fprintf(stderr, "Transform Error: %s\n", errorStr);
        }
    }

    // Clean up any allocated destination buffers
    if (dstBufs[0]) {
        tj3Free(dstBufs[0]);
    }

    // Set an ICC profile
    unsigned char iccProfile[] = {0x00, 0x01, 0x02}; // Dummy ICC profile data
    if (tj3SetICCProfile(handle, iccProfile, sizeof(iccProfile)) != 0) {
        char *errorStr = tj3GetErrorStr(handle);
        if (errorStr) {
            fprintf(stderr, "ICC Profile Error: %s\n", errorStr);
        }
    }

    // Clean up the TurboJPEG instance
    tj3Destroy(handle);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
