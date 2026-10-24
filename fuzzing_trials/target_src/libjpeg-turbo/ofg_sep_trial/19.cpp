#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    // Define image dimensions and pixel format
    int width = 32;  // Example width
    int height = 32; // Example height
    int pixelFormat = TJPF_RGB;

    // Ensure that the input size is sufficient for the image buffer
    if (size < static_cast<size_t>(width * height * tjPixelSize[pixelFormat])) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate output buffer for YUV image
    unsigned char *yuvBuffer = (unsigned char *)malloc(tjBufSizeYUV2(width, 4, height, TJSAMP_444));
    if (!yuvBuffer) {
        tjDestroy(handle);
        return 0;
    }

    // Set padding and subsampling options
    int pitch = 0; // Use 0 for tightly packed
    int subsamp = TJSAMP_444; // No subsampling
    int flags = 0; // No special flags
    int align = 4; // Example alignment

    // Call the function under test
    tjEncodeYUV3(handle, data, width, pitch, height, pixelFormat, yuvBuffer, align, subsamp, flags);

    // Clean up
    free(yuvBuffer);
    tjDestroy(handle);

    return 0;
}