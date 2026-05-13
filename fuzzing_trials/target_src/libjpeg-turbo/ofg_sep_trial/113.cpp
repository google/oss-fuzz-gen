#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, exit early
    }

    // Define image dimensions and allocate memory for decompressed image
    int width = 64;  // Example width
    int height = 64; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    unsigned char *decompressedImage = (unsigned char *)malloc(width * height * tjPixelSize[pixelFormat]);
    if (decompressedImage == nullptr) {
        tjDestroy(handle);
        return 0; // If memory allocation fails, exit early
    }

    // Call the function-under-test
    int result = tjDecompress2(handle, data, size, decompressedImage, width, 0, height, pixelFormat, 0);

    // Clean up
    free(decompressedImage);
    tjDestroy(handle);

    return 0;
}