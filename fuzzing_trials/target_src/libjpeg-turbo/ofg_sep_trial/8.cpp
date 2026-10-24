#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == nullptr) {
        return 0;
    }

    // Define image dimensions and subsampling
    int width = 64;
    int height = 64;
    int pitch = width * 3; // Assuming 3 bytes per pixel for RGB format
    int subsampling = TJSAMP_444; // Using 4:4:4 subsampling as an example

    // Allocate memory for the destination buffer
    int destSize = tj3YUVBufSize(width, 1, height, subsampling);
    unsigned char *destBuf = (unsigned char *)malloc(destSize);
    if (destBuf == nullptr) {
        tj3Destroy(handle);
        return 0;
    }

    // Call the function-under-test
    tj3EncodeYUV8(handle, data, pitch, width, 0, height, destBuf, subsampling);

    // Clean up
    free(destBuf);
    tj3Destroy(handle);

    return 0;
}