#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Variables declaration
    tjhandle handle;
    unsigned char *srcBuf = nullptr;
    unsigned char *dstBuf = nullptr;
    int width, height, pixelFormat, padding, subsampling, dstStride;

    // Initialize variables
    handle = tjInitCompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, exit early
    }

    // Ensure that the size is large enough to extract meaningful data
    if (size < 12) {
        tjDestroy(handle);
        return 0;
    }

    // Extract width, height, pixelFormat, padding, subsampling, and dstStride from the data
    width = static_cast<int>(data[0]) + 1;
    height = static_cast<int>(data[1]) + 1;
    pixelFormat = static_cast<int>(data[2]) % TJ_NUMPF;
    padding = static_cast<int>(data[3]) % 4;
    subsampling = static_cast<int>(data[4]) % TJ_NUMSAMP;
    dstStride = static_cast<int>(data[5]) + 1;

    // Allocate memory for source and destination buffers
    srcBuf = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    dstBuf = (unsigned char *)malloc(TJBUFSIZEYUV(width, height, subsampling));

    if (srcBuf == nullptr || dstBuf == nullptr) {
        free(srcBuf);
        free(dstBuf);
        tjDestroy(handle);
        return 0;
    }

    // Copy the data into the source buffer
    size_t copySize = width * height * tjPixelSize[pixelFormat];
    if (copySize > size - 6) {
        copySize = size - 6;
    }
    memcpy(srcBuf, data + 6, copySize);

    // Call the function under test
    tjEncodeYUV(handle, srcBuf, width, 0, height, pixelFormat, dstBuf, padding, subsampling);

    // Clean up
    free(srcBuf);
    free(dstBuf);
    tjDestroy(handle);

    return 0;
}