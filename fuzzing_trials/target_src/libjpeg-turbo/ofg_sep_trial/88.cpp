#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0;
    }

    // Ensure that the input size is reasonable
    if (size < 1) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for the YUV buffer
    int width = 640;  // Example width
    int height = 480; // Example height
    int yuvSize = tjBufSizeYUV2(width, 4, height, TJSAMP_444);
    unsigned char *yuvBuffer = (unsigned char *)malloc(yuvSize);
    if (yuvBuffer == NULL) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tjDecompressToYUV(handle, (unsigned char *)data, (unsigned long)size, yuvBuffer, 4);

    // Clean up
    free(yuvBuffer);
    tjDestroy(handle);

    return 0;
}