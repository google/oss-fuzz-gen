#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Initialize variables for tjCompress2
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    const unsigned char *srcBuf = data;
    int width = 100; // Example width
    int pitch = 0; // Setting pitch to 0 means it will be calculated as width * pixelSize
    int height = 100; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    unsigned char *jpegBuf = nullptr;
    unsigned long jpegSize = 0;
    int jpegSubsamp = TJSAMP_444; // Example subsampling
    int jpegQual = 75; // Example quality
    int flags = 0; // Example flags

    // Call the function-under-test
    int result = tjCompress2(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize, jpegSubsamp, jpegQual, flags);

    // Free the JPEG buffer if it was allocated
    if (jpegBuf != nullptr) {
        tjFree(jpegBuf);
    }

    // Destroy the TurboJPEG compressor handle
    tjDestroy(handle);

    return 0;
}