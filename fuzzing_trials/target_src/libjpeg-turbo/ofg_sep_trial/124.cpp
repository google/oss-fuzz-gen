#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

// Define J16SAMPLE as a 16-bit sample type, typically uint16_t
typedef uint16_t J16SAMPLE;

extern "C" int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for the image buffer (J16SAMPLE)
    int width = 100; // Example width
    int height = 100; // Example height
    int pixelFormat = TJPF_RGB; // Example pixel format
    int flags = 0; // Example flags
    size_t bufferSize = width * height * tjPixelSize[pixelFormat];
    J16SAMPLE *imageBuffer = (J16SAMPLE *)malloc(bufferSize * sizeof(J16SAMPLE));
    if (imageBuffer == NULL) {
        tj3Destroy(handle);
        return 0;
    }

    // Fill the image buffer with non-zero data
    memset(imageBuffer, 1, bufferSize * sizeof(J16SAMPLE));

    // Use the data as the filename
    char filename[256];
    size_t filenameSize = size < 255 ? size : 255;
    memcpy(filename, data, filenameSize);
    filename[filenameSize] = '\0'; // Null-terminate the filename

    // Call the function under test
    int result = tj3SaveImage16(handle, filename, imageBuffer, width, 0, pixelFormat, flags);

    // Clean up
    free(imageBuffer);
    tj3Destroy(handle);

    return 0;
}