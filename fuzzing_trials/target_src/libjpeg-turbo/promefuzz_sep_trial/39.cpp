// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tj3YUVBufSize at turbojpeg.c:971:18 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tj3CompressFromYUV8 at turbojpeg.c:1429:15 in turbojpeg.h
// tj3DecompressToYUV8 at turbojpeg.c:2341:15 in turbojpeg.h
// tjFree at turbojpeg.c:896:16 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <turbojpeg.h>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 4) return 0;

    int width = *reinterpret_cast<const int*>(Data);
    int align = *reinterpret_cast<const int*>(Data + sizeof(int));
    int height = *reinterpret_cast<const int*>(Data + 2 * sizeof(int));
    int subsamp = *reinterpret_cast<const int*>(Data + 3 * sizeof(int));

    // Test tj3YUVBufSize
    size_t yuvSize = tj3YUVBufSize(width, align, height, subsamp);
    if (yuvSize == 0) return 0; // Invalid parameters, skip further tests

    // Create a TurboJPEG instance for compression and decompression
    tjhandle handle = tjInitCompress();
    if (!handle) return 0;

    // Allocate buffers for YUV and JPEG data
    unsigned char* yuvBuf = static_cast<unsigned char*>(malloc(yuvSize));
    unsigned char* jpegBuf = nullptr;
    size_t jpegSize = 0;

    if (yuvBuf) {
        // Test tj3CompressFromYUV8
        if (tj3CompressFromYUV8(handle, yuvBuf, width, align, height, &jpegBuf, &jpegSize) == 0) {
            // Test tj3DecompressToYUV8
            unsigned char* dstBuf = static_cast<unsigned char*>(malloc(yuvSize));
            if (dstBuf) {
                tj3DecompressToYUV8(handle, jpegBuf, jpegSize, dstBuf, align);
                free(dstBuf);
            }
        }

        // Free JPEG buffer if it was allocated
        if (jpegBuf) tjFree(jpegBuf);

        free(yuvBuf);
    }

    // Cleanup TurboJPEG instance
    tjDestroy(handle);

    return 0;
}