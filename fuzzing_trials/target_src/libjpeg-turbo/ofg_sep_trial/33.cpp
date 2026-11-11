#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure data is large enough to contain a valid string for the filename
    if (size < 1) return 0;

    // Allocate memory for the filename and copy data into it
    char *filename = static_cast<char *>(malloc(size + 1));
    if (!filename) return 0;
    memcpy(filename, data, size);
    filename[size] = '\0';  // Null-terminate the string

    // Initialize parameters for tjLoadImage
    int width = 1;
    int pitch = 0;
    int height = 1;
    int pixelFormat = TJPF_RGB;  // Using a valid pixel format
    int flags = 0;

    // Call the function-under-test
    unsigned char *imageBuffer = tjLoadImage(filename, &width, pitch, &height, &pixelFormat, flags);

    // Free allocated resources
    if (imageBuffer) tjFree(imageBuffer);
    free(filename);

    return 0;
}