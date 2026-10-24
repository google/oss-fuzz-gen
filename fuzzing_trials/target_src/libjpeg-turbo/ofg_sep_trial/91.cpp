#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    // Ensure that the data size is sufficient for the input parameters
    if (size < 12) {
        tjDestroy(handle);
        return 0;
    }

    // Set up the input parameters
    unsigned char *srcBuf = const_cast<unsigned char *>(data);
    int width = 64;  // Example width
    int pitch = 64;  // Example pitch
    int height = 64; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format

    // Allocate memory for the destination buffer
    int yuvSize = tjBufSizeYUV2(width, pitch, height, pixelFormat);
    unsigned char *dstBuf = (unsigned char *)malloc(yuvSize);
    if (!dstBuf) {
        tjDestroy(handle);
        return 0;
    }

    // Set up the remaining parameters
    int pad = 4; // Example padding
    int flags = 0; // Example flags

    // Call the function-under-test
    tjEncodeYUV2(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, pad, flags);

    // Clean up
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}