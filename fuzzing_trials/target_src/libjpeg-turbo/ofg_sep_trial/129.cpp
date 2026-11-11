#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Ensure the data size is large enough to extract parameters
    if (size < 12) return 0;

    // Initialize tjhandle
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (!handle) return 0;

    // Extract parameters from the data
    const char *filename = reinterpret_cast<const char *>(data);
    int width = static_cast<int>(data[0]) + 1;  // Ensure width is non-zero
    int height = static_cast<int>(data[1]) + 1; // Ensure height is non-zero
    int pitch = width * sizeof(uint16_t);
    int pixelFormat = TJPF_RGB;

    // Allocate memory for uint16_t array
    uint16_t *samples = new uint16_t[width * height];
    if (!samples) {
        tj3Destroy(handle);
        return 0;
    }

    // Fill the samples array with data
    for (int i = 0; i < width * height; ++i) {
        samples[i] = static_cast<uint16_t>(data[i % size]);
    }

    // Call the function-under-test
    int result = tj3SaveImage16(handle, filename, samples, width, pitch, height, pixelFormat);

    // Clean up
    delete[] samples;
    tj3Destroy(handle);

    return 0;
}