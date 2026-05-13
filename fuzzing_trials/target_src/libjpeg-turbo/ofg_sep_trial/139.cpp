#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Initialize the TurboJPEG decompressor handle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Ensure the input data is large enough to contain a valid JPEG header
    if (size < 2) {
        tjDestroy(handle);
        return 0;
    }

    // Define the output buffer and dimensions
    int width = 1;  // Minimum width
    int height = 1; // Minimum height
    unsigned short *outputBuffer = new unsigned short[width * height * 3]; // Assuming RGB output

    // Call the function-under-test
    int result = tj3Decompress16(handle, data, size, outputBuffer, width, height);

    // Clean up
    delete[] outputBuffer;
    tjDestroy(handle);

    return result;
}