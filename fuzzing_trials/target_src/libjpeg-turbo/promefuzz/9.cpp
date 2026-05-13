// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tj3YUVBufSize at turbojpeg.c:971:18 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tj3CompressFromYUV8 at turbojpeg.c:1429:15 in turbojpeg.h
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tj3YUVBufSize at turbojpeg.c:971:18 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tj3DecompressToYUVPlanes8 at turbojpeg.c:2125:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
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
#include <turbojpeg.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize TurboJPEG handle for compression and decompression
    tjhandle handle = tjInitCompress();
    if (!handle) return 0;

    // Choose random parameters for the test
    int width = 256;  // Example width
    int height = 256; // Example height
    int align = 4;    // Example alignment (must be a power of 2)
    int subsamp = TJSAMP_420; // Example subsampling
    int pixelFormat = TJPF_RGB; // Example pixel format

    // Calculate buffer sizes
    size_t yuvBufSize = tj3YUVBufSize(width, align, height, subsamp);
    unsigned char *yuvBuf = static_cast<unsigned char*>(malloc(yuvBufSize));
    if (!yuvBuf) {
        tjDestroy(handle);
        return 0;
    }

    // Fill the YUV buffer with data
    memcpy(yuvBuf, Data, std::min(Size, yuvBufSize));

    // Prepare JPEG buffer
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Compress from YUV
    tj3CompressFromYUV8(handle, yuvBuf, width, align, height, &jpegBuf, &jpegSize);

    // If compression was successful, try to decompress
    if (jpegSize > 0 && jpegBuf) {
        tjhandle decompressHandle = tjInitDecompress();
        if (decompressHandle) {
            unsigned char *dstPlanes[3] = {nullptr, nullptr, nullptr};
            int strides[3] = {0, 0, 0};

            // Allocate memory for Y, U, V planes
            size_t planeSize = tj3YUVBufSize(width, align, height, subsamp);
            for (int i = 0; i < 3; i++) {
                dstPlanes[i] = static_cast<unsigned char*>(malloc(planeSize));
                if (!dstPlanes[i]) {
                    for (int j = 0; j < i; j++) free(dstPlanes[j]);
                    tjDestroy(decompressHandle);
                    free(jpegBuf);
                    free(yuvBuf);
                    tjDestroy(handle);
                    return 0;
                }
            }

            // Decompress JPEG to YUV planes
            tj3DecompressToYUVPlanes8(decompressHandle, jpegBuf, jpegSize, dstPlanes, strides);

            // Free allocated YUV plane memory
            for (int i = 0; i < 3; i++) {
                free(dstPlanes[i]);
            }

            tjDestroy(decompressHandle);
        }
    }

    // Free JPEG buffer if it was allocated
    if (jpegBuf) tjFree(jpegBuf);

    // Free YUV buffer
    free(yuvBuf);

    // Destroy the TurboJPEG handle
    tjDestroy(handle);

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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    