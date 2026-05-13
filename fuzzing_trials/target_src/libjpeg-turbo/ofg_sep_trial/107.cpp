#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0; // If handle initialization fails, exit early
    }

    // Ensure the input size is sufficient for width, height, and pixel format
    if (size < 12) {
        tjDestroy(handle);
        return 0;
    }

    // Extract width, height, and pixel format from the input data
    int width = data[0] | (data[1] << 8);
    int height = data[2] | (data[3] << 8);
    int pixelFormat = data[4] % TJ_NUMPF; // Ensure pixel format is valid

    // Calculate the minimum buffer size needed for the image
    int pitch = width * tjPixelSize[pixelFormat];
    size_t minBufferSize = pitch * height;

    // Check if the input data size is sufficient for the image buffer
    if (size < minBufferSize + 12) {
        tjDestroy(handle);
        return 0;
    }

    // Set the image buffer to the remaining data
    unsigned char *srcBuf = const_cast<unsigned char *>(data + 12);

    // Allocate memory for the YUV buffer
    unsigned char *yuvBuf = new unsigned char[tjBufSizeYUV2(width, pitch, height, TJ_420)];

    // Call the function under test
    int result = tjEncodeYUV(handle, srcBuf, width, pitch, height, pixelFormat, yuvBuf, 4, TJ_420);

    // Clean up
    delete[] yuvBuf;
    tjDestroy(handle);

    return 0;
}