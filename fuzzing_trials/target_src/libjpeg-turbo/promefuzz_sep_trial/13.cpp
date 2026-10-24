// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3Init at turbojpeg.c:538:20 in turbojpeg.h
// tj3DecompressHeader at turbojpeg.c:1815:15 in turbojpeg.h
// tj3TransformBufSize at turbojpeg.c:2831:18 in turbojpeg.h
// tj3Transform at turbojpeg.c:2870:15 in turbojpeg.h
// tj3GetErrorStr at turbojpeg.c:618:17 in turbojpeg.h
// tj3Destroy at turbojpeg.c:580:16 in turbojpeg.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <turbojpeg.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static void writeDummyFile(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize TurboJPEG instance for transformation
    tjhandle handle = tj3Init(TJINIT_TRANSFORM);
    if (!handle) return 0;

    // Prepare transformation parameters
    tjtransform transform;
    memset(&transform, 0, sizeof(tjtransform));
    transform.op = Data[0] % 8; // Choose a transform operation
    transform.r.x = 0;
    transform.r.y = 0;
    transform.r.w = 0;
    transform.r.h = 0;
    transform.customFilter = nullptr;

    // Dummy buffer for destination
    unsigned char *dstBufs[1] = { nullptr };
    size_t dstSizes[1] = { 0 };

    // Write data to dummy file for possible file-based operations
    writeDummyFile(Data, Size);

    // Decompress header (primes the decompressor)
    if (tj3DecompressHeader(handle, Data, Size) == 0) {
        // Estimate buffer size for transformation
        size_t bufSize = tj3TransformBufSize(handle, &transform);
        if (bufSize > 0) {
            dstBufs[0] = (unsigned char *)malloc(bufSize);
            if (dstBufs[0]) {
                dstSizes[0] = bufSize;

                // Attempt to perform the transformation
                int result = tj3Transform(handle, Data, Size, 1, dstBufs, dstSizes, &transform);
                if (result == -1) {
                    // Handle error
                    char *errStr = tj3GetErrorStr(handle);
                    if (errStr) {
                        fprintf(stderr, "Error: %s\n", errStr);
                    }
                }

                free(dstBufs[0]);
            }
        }
    }

    // Clean up
    tj3Destroy(handle);
    return 0;
}