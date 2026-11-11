#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0; // Not enough data to proceed
    }

    // Initialize tjhandle
    tjhandle handle = tjInitDecompress();
    if (!handle) {
        return 0; // Failed to initialize
    }

    // Parameters for tjDecodeYUV
    const unsigned char *srcBuf = data;
    int pad = 1; // Assuming 1 for padding
    int subsamp = TJSAMP_444; // Assuming 4:4:4 subsampling
    int width = 16; // Arbitrary width
    int height = 16; // Arbitrary height
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * 3); // RGB buffer
    if (!dstBuf) {
        tjDestroy(handle);
        return 0; // Failed to allocate memory
    }
    int pitch = 0; // Default pitch
    int pixelFormat = TJPF_RGB; // Assuming RGB pixel format
    int flags = 0; // No flags

    // Call the function-under-test
    tjDecodeYUV(handle, srcBuf, pad, subsamp, dstBuf, width, pitch, height, pixelFormat, flags);

    // Clean up
    tjDestroy(handle);
    free(dstBuf);

    return 0;
}