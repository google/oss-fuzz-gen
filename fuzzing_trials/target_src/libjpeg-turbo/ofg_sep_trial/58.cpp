#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return 0;
    }

    const unsigned char *srcBuf = data;
    int width = 100;  // Arbitrary non-zero width
    int height = 100; // Arbitrary non-zero height
    int pitch = width * 3; // Assuming 3 bytes per pixel (RGB)
    int subsamp = TJSAMP_420; // Common subsampling
    unsigned char *dstBuf = NULL;
    int dstSize = 0;

    // Allocate memory for the destination buffer
    dstBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, pitch, height, subsamp));
    if (dstBuf == NULL) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    tj3EncodeYUVPlanes8(handle, srcBuf, width, pitch, height, subsamp, &dstBuf, &dstSize);

    // Clean up
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}