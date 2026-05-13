#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Declare and initialize all necessary variables
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, exit early
    }

    unsigned char *srcBuf = const_cast<unsigned char *>(data);
    int width = 10;  // Arbitrary non-zero width
    int height = 10; // Arbitrary non-zero height
    int pixelFormat = TJPF_RGB; // Assuming RGB format for simplicity
    int pitch = width * tjPixelSize[pixelFormat]; // Calculate pitch based on width and pixel format

    unsigned char *dstBuf = nullptr; // Destination buffer to hold compressed data
    unsigned long dstSize = 0; // Size of the compressed data
    int jpegSubsamp = TJSAMP_444; // Chroma subsampling option
    int jpegQual = 75; // Quality of the JPEG image
    int flags = 0; // No special flags

    // Allocate memory for the destination buffer
    dstBuf = static_cast<unsigned char *>(malloc(TJBUFSIZE(width, height)));
    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function-under-test
    int result = tjCompress2(handle, srcBuf, width, pitch, height, pixelFormat, &dstBuf, &dstSize, jpegSubsamp, jpegQual, flags);

    // Clean up
    if (dstBuf != nullptr) {
        tjFree(dstBuf);
    }
    tjDestroy(handle);

    return 0;
}