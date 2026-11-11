#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    tjhandle handle = tjInitCompress();
    const unsigned char *srcBuf = data;
    int width = 16;  // Example width, must be a multiple of 8
    int height = 16; // Example height, must be a multiple of 8
    int strides = width; // Assuming strides equal to width for simplicity
    int subsamp = TJSAMP_420; // Example subsampling
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;
    int jpegQual = 75; // Example JPEG quality
    int flags = 0; // No flags

    // Check if the handle was created successfully
    if (handle == nullptr) {
        return 0;
    }

    // Call the function-under-test
    int result = tjCompressFromYUV(handle, srcBuf, width, strides, height, subsamp, &jpegBuf, &jpegSize, jpegQual, flags);

    // Clean up resources
    if (jpegBuf != nullptr) {
        tjFree(jpegBuf);
    }
    tjDestroy(handle);

    return 0;
}