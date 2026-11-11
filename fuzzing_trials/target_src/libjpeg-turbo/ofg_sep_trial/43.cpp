extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Initialize the TurboJPEG decompressor handle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Allocate memory for the decompressed image
    int width = 100;  // Example width
    int height = 100; // Example height
    int pixelFormat = TJPF_RGB; // RGB pixel format
    int pitch = width * tjPixelSize[pixelFormat];
    unsigned char *dstBuffer = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (dstBuffer == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Set default values for the parameters
    int subsamp = TJSAMP_444; // Example subsampling
    int flags = 0; // No flags

    // Call the function-under-test
    tjDecompress(handle, (unsigned char *)data, (unsigned long)size, dstBuffer, width, pitch, height, pixelFormat, flags);

    // Clean up
    free(dstBuffer);
    tjDestroy(handle);

    return 0;
}