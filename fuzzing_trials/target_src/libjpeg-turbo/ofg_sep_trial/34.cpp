#include <cstdint>
#include <cstdlib>
#include <cstring> // Include for memcpy

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    unsigned char* tjLoadImage(const char*, int*, int, int*, int*, int);
}

extern "C" int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Ensure the data size is large enough to contain a valid file path
    if (size < 1) {
        return 0;
    }

    // Create a null-terminated string from the input data
    char *filePath = (char *)malloc(size + 1);
    if (filePath == NULL) {
        return 0;
    }
    memcpy(filePath, data, size);
    filePath[size] = '\0';

    int width = 1;  // Initialize width with a non-zero value
    int height = 1; // Initialize height with a non-zero value
    int pixelFormat = TJPF_RGB;  // Use a valid pixel format
    int outSubsamp = TJSAMP_444; // Use a valid subsampling option

    // Call the function-under-test
    unsigned char *imageBuffer = tjLoadImage(filePath, &width, 0, &height, &pixelFormat, outSubsamp);

    // Clean up
    free(filePath);

    // If imageBuffer is not NULL, free it
    if (imageBuffer != NULL) {
        tjFree(imageBuffer);
    }

    return 0;
}