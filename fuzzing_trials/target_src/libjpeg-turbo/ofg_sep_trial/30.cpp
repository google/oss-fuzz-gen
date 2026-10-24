#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for tjSaveImage
    const char *filename = "test_output.jpg"; // Filename for saving the image
    unsigned char *imageBuffer = nullptr;
    int width = 100;  // Arbitrary non-zero width
    int height = 100; // Arbitrary non-zero height
    int pitch = width * 3; // Assuming 3 bytes per pixel (RGB)
    int pixelFormat = TJPF_RGB; // Using RGB pixel format
    int flags = 0; // No specific flags

    // Allocate memory for the image buffer
    imageBuffer = (unsigned char *)malloc(width * height * 3);
    if (imageBuffer == nullptr) {
        return 0; // Exit if memory allocation fails
    }

    // Copy data into imageBuffer to ensure it is not NULL
    size_t copySize = (size < width * height * 3) ? size : width * height * 3;
    memcpy(imageBuffer, data, copySize);

    // Call the function-under-test
    int result = tjSaveImage(filename, imageBuffer, width, pitch, height, pixelFormat, flags);

    // Free the allocated memory
    free(imageBuffer);

    return 0;
}