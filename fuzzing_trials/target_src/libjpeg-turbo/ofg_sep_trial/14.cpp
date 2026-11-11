#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Create a temporary file to simulate an image file input
    const char *tempFilename = "temp_image.jpg";
    FILE *tempFile = fopen(tempFilename, "wb");
    if (tempFile == nullptr) {
        tjDestroy(handle);
        return 0;
    }
    fwrite(data, 1, size, tempFile);
    fclose(tempFile);

    // Initialize parameters for tj3LoadImage16
    int width = 0;
    int pitch = 0;
    int height = 0;
    int pixelFormat = TJPF_RGB;

    // Call the function-under-test
    unsigned short *imageBuffer = tj3LoadImage16(handle, tempFilename, &width, pitch, &height, &pixelFormat);

    // Clean up
    if (imageBuffer != nullptr) {
        tj3Free(imageBuffer);  // Use tj3Free instead of tjFree for unsigned short*
    }
    tjDestroy(handle);
    remove(tempFilename);

    return 0;
}