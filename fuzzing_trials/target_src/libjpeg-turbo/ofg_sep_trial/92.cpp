#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    tjhandle handle = tjInitCompress();
    unsigned char *srcBuf = nullptr;
    unsigned char *dstBuf = nullptr;
    int width = 1; // Setting to a minimal non-zero value
    int height = 1; // Setting to a minimal non-zero value
    int pitch = 0; // Setting to 0 for automatic calculation
    int pixelFormat = TJPF_RGB; // Using a valid pixel format
    int pad = 1; // Setting to a minimal non-zero value
    int subsamp = TJSAMP_444; // Using a valid subsampling option

    // Allocate memory for source and destination buffers
    srcBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    dstBuf = (unsigned char *)malloc(tjBufSizeYUV2(width, pad, height, subsamp));

    if (srcBuf == nullptr || dstBuf == nullptr) {
        if (srcBuf) free(srcBuf);
        if (dstBuf) free(dstBuf);
        tjDestroy(handle);
        return 0;
    }

    // Fill the source buffer with data if available
    if (size > 0) {
        memcpy(srcBuf, data, size < (width * height * tjPixelSize[pixelFormat]) ? size : (width * height * tjPixelSize[pixelFormat]));
    }

    // Call the function under test
    tjEncodeYUV2(handle, srcBuf, width, pitch, height, pixelFormat, dstBuf, pad, subsamp);

    // Clean up
    free(srcBuf);
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}