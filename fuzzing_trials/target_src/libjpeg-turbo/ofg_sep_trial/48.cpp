#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, return early
    }

    // Allocate a buffer for the decompressed image
    int width = 800;  // Example width
    int height = 600; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int pitch = width * tjPixelSize[pixelFormat];
    unsigned char *dstBuf = (unsigned char *)malloc(pitch * height);
    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0; // If memory allocation fails, return early
    }

    // Set decompression parameters
    int subsamp = TJSAMP_444; // Example subsampling
    int flags = 0; // Example flags

    // Call the function-under-test
    tjDecompress2(handle, data, (unsigned long)size, dstBuf, width, pitch, height, pixelFormat, flags);

    // Clean up
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}