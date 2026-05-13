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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize TurboJPEG instance
    tjhandle handle = tj3Init(TJINIT_TRANSFORM);
    if (!handle) {
        std::cerr << "Failed to initialize TurboJPEG: " << tj3GetErrorStr(NULL) << std::endl;
        return 0;
    }

    // Prepare dummy JPEG data if needed
    const unsigned char *jpegBuf = Data;
    size_t jpegSize = Size;

    // Prepare transformation
    tjtransform transform;
    memset(&transform, 0, sizeof(tjtransform));
    transform.op = Data[0] % 8; // Random operation

    // Prepare destination buffers
    int n = 1;
    unsigned char *dstBufs[1] = { nullptr };
    size_t dstSizes[1] = { 0 };

    // Perform transformation
    int result = tj3Transform(handle, jpegBuf, jpegSize, n, dstBufs, dstSizes, &transform);
    if (result != 0) {
        std::cerr << "Transformation failed: " << tj3GetErrorStr(handle) << std::endl;
    }

    // Clean up destination buffers
    for (int i = 0; i < n; i++) {
        if (dstBufs[i]) {
            tjFree(dstBufs[i]);
        }
    }

    // Set ICC profile
    unsigned char iccProfile[128] = {0}; // Dummy ICC profile
    result = tj3SetICCProfile(handle, iccProfile, sizeof(iccProfile));
    if (result != 0) {
        std::cerr << "Set ICC profile failed: " << tj3GetErrorStr(handle) << std::endl;
    }

    // Estimate buffer size
    size_t bufferSize = tj3TransformBufSize(handle, &transform);
    if (bufferSize == 0) {
        std::cerr << "Buffer size estimation failed: " << tj3GetErrorStr(handle) << std::endl;
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
