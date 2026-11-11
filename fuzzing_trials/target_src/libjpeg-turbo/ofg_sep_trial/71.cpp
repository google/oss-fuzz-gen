#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Include the correct path for turbojpeg.h
extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

// Define a non-NULL string for the filename
#define FILENAME "test_image.jpg"

// Define a sample width, height, and pitch
#define WIDTH 10
#define HEIGHT 10
#define PITCH (WIDTH * sizeof(uint16_t))  // Corrected to use uint16_t

extern "C" int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the image buffer
    if (size < WIDTH * HEIGHT * sizeof(uint16_t)) {  // Corrected to use uint16_t
        return 0;
    }

    // Initialize TurboJPEG handle
    tjhandle handle = tj3Init(TJINIT_COMPRESS);
    if (handle == NULL) {
        return 0;
    }

    // Allocate memory for the image buffer
    uint16_t *imageBuffer = (uint16_t *)malloc(WIDTH * HEIGHT * sizeof(uint16_t));  // Corrected to use uint16_t
    if (imageBuffer == NULL) {
        tj3Destroy(handle);
        return 0;
    }

    // Copy data into the image buffer
    memcpy(imageBuffer, data, WIDTH * HEIGHT * sizeof(uint16_t));  // Corrected to use uint16_t

    // Call the function under test
    int result = tj3SaveImage16(handle, FILENAME, imageBuffer, WIDTH, PITCH, HEIGHT, TJPF_RGB);

    // Clean up
    free(imageBuffer);
    tj3Destroy(handle);

    return 0;
}