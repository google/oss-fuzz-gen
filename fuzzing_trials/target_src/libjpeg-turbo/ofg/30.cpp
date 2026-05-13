#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    if (size < 4) return 0; // Ensure there is enough data for width, height, etc.

    // Initialize the TurboJPEG compressor
    tjhandle handle = tjInitCompress();
    if (!handle) return 0;

    // Extract some parameters from the input data
    int width = data[0] + 1;  // Avoid zero width
    int height = data[1] + 1; // Avoid zero height
    int pixelFormat = data[2] % TJ_NUMPF; // Valid pixel format
    int quality = data[3] % 101; // JPEG quality (0-100)

    // Calculate the number of bytes needed for the image buffer
    int pixelSize = tjPixelSize[pixelFormat];
    int imageSize = width * height * pixelSize;

    // Ensure the provided data is sufficient for the image buffer
    if (size < 4 + imageSize) {
        tjDestroy(handle);
        return 0;
    }

    // Set up the image buffer
    const unsigned char *imageBuffer = data + 4;

    // Prepare output buffer
    unsigned char *jpegBuffer = nullptr;
    unsigned long jpegSize = 0;

    // Call the function-under-test
    int result = tjCompress2(handle, imageBuffer, width, 0, height, pixelFormat, &jpegBuffer, &jpegSize, TJSAMP_444, quality, TJFLAG_FASTDCT);

    // Free the JPEG buffer if it was allocated
    if (jpegBuffer) {
        tjFree(jpegBuffer);
    }

    // Clean up the TurboJPEG handle
    tjDestroy(handle);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
