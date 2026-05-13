#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Initialize the TurboJPEG decompressor handle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Initialization failed, exit early
    }

    // Allocate a buffer for the YUV data
    int width = 640;  // Example width
    int height = 480; // Example height
    int yuvSize = tjBufSizeYUV2(width, 4, height, TJ_420);
    unsigned char *yuvBuffer = static_cast<unsigned char *>(malloc(yuvSize));
    if (yuvBuffer == nullptr) {
        tjDestroy(handle);
        return 0; // Memory allocation failed, exit early
    }

    // Call the function-under-test
    int result = tj3DecompressToYUV8(handle, data, size, yuvBuffer, 0);

    // Clean up
    free(yuvBuffer);
    tjDestroy(handle);

    return 0;
}