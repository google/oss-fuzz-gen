#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    // Initialize the TurboJPEG decompressor handle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Exit if initialization fails
    }

    // Allocate memory for the YUV planes
    unsigned char *yuvPlanes[3];
    int yuvStrides[3] = {0, 0, 0}; // Initialize strides to zero

    // Assume a maximum image width and height for testing purposes
    const int maxWidth = 1920;
    const int maxHeight = 1080;

    // Calculate the size of each YUV plane
    int yuvSizes[3];
    yuvSizes[0] = maxWidth * maxHeight; // Y plane
    yuvSizes[1] = maxWidth * maxHeight / 4; // U plane
    yuvSizes[2] = maxWidth * maxHeight / 4; // V plane

    // Allocate memory for each YUV plane
    for (int i = 0; i < 3; ++i) {
        yuvPlanes[i] = static_cast<unsigned char *>(malloc(yuvSizes[i]));
        if (yuvPlanes[i] == nullptr) {
            tjDestroy(handle);
            return 0; // Exit if memory allocation fails
        }
    }

    // Call the function-under-test
    int result = tj3DecompressToYUVPlanes8(handle, data, size, yuvPlanes, yuvStrides);

    // Free allocated memory
    for (int i = 0; i < 3; ++i) {
        free(yuvPlanes[i]);
    }

    // Clean up the TurboJPEG handle
    tjDestroy(handle);

    return 0;
}