#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return 0;
    }

    const unsigned char *yuvPlanes[3];
    unsigned char *compressedImage = NULL;
    size_t compressedSize = 0;
    int strides[3];
    int width = 64;  // Example width
    int height = 64; // Example height
    int subsamp = TJSAMP_420; // Example subsampling

    // Allocate memory for YUV planes
    for (int i = 0; i < 3; i++) {
        yuvPlanes[i] = (const unsigned char *)malloc(width * height);
        if (yuvPlanes[i] == NULL) {
            tjDestroy(handle);
            return 0;
        }
        memset((void*)yuvPlanes[i], 0, width * height);
        strides[i] = width;
    }

    // Allocate memory for compressed image
    compressedImage = (unsigned char *)malloc(TJBUFSIZE(width, height));
    if (compressedImage == NULL) {
        for (int i = 0; i < 3; i++) {
            free((void*)yuvPlanes[i]);
        }
        tjDestroy(handle);
        return 0;
    }

    // Call the function under test
    tj3CompressFromYUVPlanes8(handle, yuvPlanes, width, strides, height, &compressedImage, &compressedSize);

    // Clean up
    for (int i = 0; i < 3; i++) {
        free((void*)yuvPlanes[i]);
    }
    free(compressedImage);
    tjDestroy(handle);

    return 0;
}