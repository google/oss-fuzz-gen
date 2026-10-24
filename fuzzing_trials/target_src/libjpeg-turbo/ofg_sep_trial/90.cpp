#include <cstdint>
#include <cstdlib>

extern "C" {
#include "/src/libjpeg-turbo.main/src/turbojpeg.h"
#include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
#include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (!handle) {
        return 0; // If initialization fails, exit early
    }

    // Ensure size is sufficient for at least one pixel
    if (size < sizeof(uint16_t)) {
        tj3Destroy(handle);
        return 0;
    }

    // Prepare input image buffer
    const uint16_t *srcBuf = reinterpret_cast<const uint16_t *>(data);
    int width = 1;  // Minimal width
    int height = static_cast<int>(size / (width * sizeof(uint16_t)));  // Calculate height based on available size
    int pitch = width * sizeof(uint16_t);
    int pixelFormat = TJPF_RGBX;  // Example pixel format

    // Prepare output buffer
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;

    // Call the function-under-test
    int result = tj3Compress16(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize);

    // Clean up
    if (jpegBuf) {
        tj3Free(jpegBuf);
    }
    tj3Destroy(handle);

    return 0;
}