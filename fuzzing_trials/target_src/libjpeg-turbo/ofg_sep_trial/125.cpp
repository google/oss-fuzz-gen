#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    tjhandle handle = tjInitDecompress();
    const unsigned char *yuvPlanes[3];
    int strides[3];
    unsigned char *dstBuffer;
    int width = 16;  // Example width
    int height = 16; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int flags = 0;   // Example flags

    if (size < width * height * 3) {
        tjDestroy(handle);
        return 0;
    }

    // Initialize YUV planes with pointers into the data
    yuvPlanes[0] = data;
    yuvPlanes[1] = data + (width * height);
    yuvPlanes[2] = data + (width * height * 2);

    // Initialize strides
    strides[0] = width;
    strides[1] = width / 2;
    strides[2] = width / 2;

    // Allocate destination buffer
    dstBuffer = new unsigned char[width * height * tjPixelSize[pixelFormat]];

    // Call the function-under-test
    tj3DecodeYUVPlanes8(handle, yuvPlanes, strides, dstBuffer, width, 0, height, pixelFormat);

    // Clean up
    delete[] dstBuffer;
    tjDestroy(handle);

    return 0;
}