// This fuzz driver is generated for library libjpeg-turbo, aiming to fuzz the following functions:
// tjInitDecompress at turbojpeg.c:1808:20 in turbojpeg.h
// tj3DecompressToYUVPlanes8 at turbojpeg.c:2125:15 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjInitCompress at turbojpeg.c:1157:20 in turbojpeg.h
// tjDestroy at turbojpeg.c:601:15 in turbojpeg.h
// tjBufSize at turbojpeg.c:933:25 in turbojpeg.h
// tjCompress at turbojpeg.c:1235:15 in turbojpeg.h
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

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < 100) return 0; // Ensure there's enough data

    // Initialize TurboJPEG handle for decompression
    tjhandle handle = tjInitDecompress();
    if (!handle) return 0;

    // Prepare parameters for tj3DecompressToYUVPlanes8
    unsigned char *jpegBuf = const_cast<unsigned char*>(Data);
    size_t jpegSize = Size;
    unsigned char *dstPlanes[3] = { nullptr, nullptr, nullptr };
    int strides[3] = { 0, 0, 0 };

    // Allocate memory for YUV planes (assuming worst-case sizes for simplicity)
    int width = 128, height = 128; // Example dimensions
    for (int i = 0; i < 3; i++) {
        dstPlanes[i] = (unsigned char *)malloc(width * height);
        if (!dstPlanes[i]) goto cleanup;
    }

    // Call the target function
    tj3DecompressToYUVPlanes8(handle, jpegBuf, jpegSize, dstPlanes, strides);

cleanup:
    // Free allocated memory
    for (int i = 0; i < 3; i++) {
        if (dstPlanes[i]) free(dstPlanes[i]);
    }
    // Destroy the TurboJPEG handle
    tjDestroy(handle);

    // Initialize TurboJPEG handle for compression
    handle = tjInitCompress();
    if (!handle) return 0;

    // Prepare parameters for tjCompress
    unsigned char *srcBuf = const_cast<unsigned char*>(Data);

    // Calculate pitch and check if buffer is large enough
    int pixelSize = 3; // Assuming RGB format
    int pitch = width * pixelSize;
    if (Size < static_cast<size_t>(width * height * pixelSize)) {
        tjDestroy(handle);
        return 0;
    }

    unsigned char *dstBuf = nullptr;
    unsigned long compressedSize = 0;
    int jpegSubsamp = TJSAMP_420; // Example subsampling
    int jpegQual = 75; // Example quality
    int flags = 0;

    // Estimate the buffer size for the compressed image
    unsigned long dstBufSize = tjBufSize(width, height, jpegSubsamp);
    dstBuf = (unsigned char *)malloc(dstBufSize);

    // Call the target function
    tjCompress(handle, srcBuf, width, pitch, height, pixelSize, dstBuf, &compressedSize, jpegSubsamp, jpegQual, flags);

    // Free the output buffer if it was allocated
    if (dstBuf) free(dstBuf);

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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    