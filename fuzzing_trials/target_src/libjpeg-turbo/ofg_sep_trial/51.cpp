#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    // Alternatively, you can use one of the other paths if applicable:
    // #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    // #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0; // Exit if initialization fails
    }

    // Define parameters for tjDecompressToYUV2
    unsigned char *jpegBuf = const_cast<unsigned char *>(data);
    unsigned long jpegSize = static_cast<unsigned long>(size);

    // Arbitrary width and height for the output image
    int width = 128;
    int height = 128;

    // YUV buffer size calculation
    int yuvSize = tjBufSizeYUV2(width, 4, height, TJ_420);
    unsigned char *yuvBuf = static_cast<unsigned char *>(malloc(yuvSize));

    // Ensure yuvBuf is not NULL
    if (yuvBuf == NULL) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tjDecompressToYUV2(handle, jpegBuf, jpegSize, yuvBuf, width, 4, height, TJ_420);

    // Clean up
    free(yuvBuf);
    tjDestroy(handle);

    return 0;
}