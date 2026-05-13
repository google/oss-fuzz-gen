#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0; // Exit if handle initialization fails
    }

    const unsigned char *yuvPlanes[3];
    int strides[3] = {0};
    unsigned char *dstBuffer = nullptr;
    int width = 0, height = 0, pitch = 0, flags = 0;

    // Ensure that data is not empty and has enough size for minimal processing
    if (size > 0) {
        // Assign data to yuvPlanes for testing
        yuvPlanes[0] = data;
        yuvPlanes[1] = data;
        yuvPlanes[2] = data;

        // Assign some values to strides, width, height, pitch, and flags
        strides[0] = strides[1] = strides[2] = static_cast<int>(size);
        width = static_cast<int>(size);
        height = static_cast<int>(size);
        pitch = static_cast<int>(size);
        flags = TJFLAG_FASTDCT;

        // Allocate memory for destination buffer
        dstBuffer = new unsigned char[size];
    }

    // Call the function-under-test
    tj3DecodeYUVPlanes8(handle, yuvPlanes, strides, dstBuffer, width, height, pitch, flags);

    // Clean up
    if (dstBuffer) {
        delete[] dstBuffer;
    }
    tjDestroy(handle);

    return 0;
}