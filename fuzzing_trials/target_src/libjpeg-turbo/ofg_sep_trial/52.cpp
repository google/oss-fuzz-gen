#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, return early
    }

    const unsigned char *jpegBuf = data;
    unsigned long jpegSize = static_cast<unsigned long>(size);

    // Assuming a maximum width and height for the YUV image
    int width = 128;
    int height = 128;
    int align = 1; // YUV alignment

    // Allocate memory for the YUV buffer
    unsigned char *yuvBuf = static_cast<unsigned char*>(malloc(tjBufSizeYUV2(width, align, height, TJ_420)));

    if (yuvBuf == nullptr) {
        tjDestroy(handle);
        return 0; // If memory allocation fails, return early
    }

    // Call the function-under-test
    int result = tjDecompressToYUV2(handle, jpegBuf, jpegSize, yuvBuf, width, align, height, TJ_420);

    // Clean up
    free(yuvBuf);
    tjDestroy(handle);

    return 0;
}