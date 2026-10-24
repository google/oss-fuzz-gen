#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    // Initialize parameters for tj3CompressFromYUV8
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == nullptr) {
        return 0;
    }

    // Extract width, height, and subsampling from the input data
    int width = data[0] + 1; // Ensure width is at least 1
    int height = data[1] + 1; // Ensure height is at least 1
    int subsampling = data[2] % 4; // Subsampling value must be valid

    // Allocate memory for the compressed image
    unsigned char *compressedImage = nullptr;
    size_t compressedSize = 0;

    // Call the function-under-test
    int result = tj3CompressFromYUV8(handle, data, width, height, subsampling, &compressedImage, &compressedSize);

    // Clean up
    if (compressedImage != nullptr) {
        tj3Free(compressedImage);
    }
    tj3Destroy(handle);

    return 0;
}