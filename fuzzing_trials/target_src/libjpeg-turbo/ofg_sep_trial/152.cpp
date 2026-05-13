#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    if (size < sizeof(uint16_t) * 3) { // Use uint16_t as a substitute for J16SAMPLE
        return 0; // Not enough data to form even a single pixel.
    }

    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return 0; // Initialization failed, exit early.
    }

    // Prepare parameters for tj3Compress16
    const uint16_t *srcBuf = reinterpret_cast<const uint16_t *>(data); // Use uint16_t
    int width = 1;  // Minimal width
    int height = 1; // Minimal height
    int pitch = width * sizeof(uint16_t); // Use uint16_t
    int pixelFormat = TJPF_RGB; // Assume RGB format for simplicity

    unsigned char *jpegBuf = NULL;
    size_t jpegSize = 0;

    // Call the function-under-test
    int result = tj3Compress16(handle, srcBuf, width, pitch, height, pixelFormat, &jpegBuf, &jpegSize);

    // Clean up
    if (jpegBuf != NULL) {
        tjFree(jpegBuf);
    }
    tjDestroy(handle);

    return 0;
}