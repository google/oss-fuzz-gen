#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return 0; // If initialization fails, return immediately
    }

    const unsigned char *srcBuf = data;
    int width = 64;  // Example width
    int height = 64; // Example height
    int pitch = width * 3; // Assuming 3 bytes per pixel (RGB)
    int subsamp = TJSAMP_444; // Example subsampling
    unsigned char *dstBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, pitch, height, subsamp));
    int dstSize = 0;

    if (dstBuf == NULL) {
        tjDestroy(handle);
        return 0; // If memory allocation fails, return immediately
    }

    // Call the function-under-test
    tj3EncodeYUVPlanes8(handle, srcBuf, width, pitch, height, subsamp, &dstBuf, &dstSize);

    // Clean up
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}