#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for tjDecompressToYUVPlanes
    tjhandle handle = tjInitDecompress();
    if (handle == NULL) {
        return 0; // If initialization fails, return immediately
    }

    unsigned long jpegSize = (unsigned long)size;
    const unsigned char *jpegBuf = data;

    // Assuming maximum dimensions for testing purposes
    int width = 128;
    int height = 128;
    int numPlanes = 3; // Y, U, V planes

    // Allocate memory for YUV planes
    unsigned char *yuvPlanes[3];
    for (int i = 0; i < numPlanes; i++) {
        yuvPlanes[i] = (unsigned char *)malloc(width * height);
        if (yuvPlanes[i] == NULL) {
            // If memory allocation fails, clean up and return
            for (int j = 0; j < i; j++) {
                free(yuvPlanes[j]);
            }
            tjDestroy(handle);
            return 0;
        }
    }

    int strides[3] = {width, width / 2, width / 2}; // Typical YUV420 strides

    // Call the function-under-test
    int result = tjDecompressToYUVPlanes(handle, jpegBuf, jpegSize, yuvPlanes, width, strides, height, 0);

    // Clean up
    for (int i = 0; i < numPlanes; i++) {
        free(yuvPlanes[i]);
    }
    tjDestroy(handle);

    return 0;
}