#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  // Include for FILE operations

// Include the correct path for turbojpeg.h
extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    unsigned short * tj3LoadImage16(tjhandle handle, const char *filename, int *width, int pitch, int *height, int *pixelFormat);
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0; // Exit if handle initialization fails
    }

    // Create a temporary filename for testing
    const char *filename = "temp_image.tiff";

    // Write the input data to the file
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        tjDestroy(handle);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Initialize other parameters
    int width = 0;
    int pitch = 0;
    int height = 0;
    int pixelFormat = TJPF_RGB;

    // Call the function-under-test
    unsigned short *image = tj3LoadImage16(handle, filename, &width, pitch, &height, &pixelFormat);

    // Clean up
    if (image != NULL) {
        free(image); // Use free instead of tjFree for unsigned short *
    }
    tjDestroy(handle);

    // Remove the temporary file
    remove(filename);

    return 0;
}