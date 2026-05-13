#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Initialize TurboJPEG handle
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == nullptr) {
        return 0;
    }

    // Allocate memory for the compressed image
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Define image parameters
    const uint16_t *srcBuf = reinterpret_cast<const uint16_t *>(data);
    int width = 16;  // Example width
    int height = 16; // Example height
    int pitch = width * sizeof(uint16_t);
    int pixelFormat = TJPF_RGBX; // Example pixel format

    // Call the function-under-test
    int result = tj3Compress16(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize);

    // Clean up
    if (jpegBuf != nullptr) {
        tj3Free(jpegBuf);
    }
    tj3Destroy(handle);

    return 0;
}