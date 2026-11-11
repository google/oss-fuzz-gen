#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"

    // Include the function-under-test
    unsigned short * tj3LoadImage16(tjhandle handle, const char *filename, int *width, int pitch, int *height, int *flags);
}

extern "C" int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    tjhandle handle = tjInitDecompress();
    const char *filename = "test_image.jpg";  // Use a dummy filename
    int width = 0;
    int height = 0;
    int pitch = 0;
    int flags = 0;
    unsigned short *image = NULL;

    if (handle == NULL) {
        return 0;
    }

    // Ensure the data is not empty
    if (size > 0) {
        // Call the function-under-test
        image = tj3LoadImage16(handle, filename, &width, pitch, &height, &flags);

        // Free the allocated image if not NULL
        if (image != NULL) {
            free(image);
        }
    }

    // Clean up
    tjDestroy(handle);

    return 0;
}