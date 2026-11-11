#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Set up the output buffer for decompression
    int width = 64;  // Example width, adjust as needed
    int height = 64; // Example height, adjust as needed
    int pixelFormat = TJPF_RGB; // Choose a pixel format
    unsigned char *outputBuffer = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (outputBuffer == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tjDecompress2(handle, data, size, outputBuffer, width, 0 /*pitch*/, height, pixelFormat, TJFLAG_FASTDCT);

    // Clean up
    free(outputBuffer);
    tjDestroy(handle);

    return 0;
}