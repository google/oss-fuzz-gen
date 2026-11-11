#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (!handle) {
        return 0;
    }

    // Define and initialize parameters for tj3CompressFromYUVPlanes8
    const unsigned char *yuvPlanes[3];
    int strides[3];
    unsigned char *jpegBuf = nullptr;
    size_t jpegSize = 0;
    int width = 2;  // Example width
    int height = 2; // Example height
    int subsamp = TJSAMP_420; // Example subsampling, can be varied

    // Ensure data is large enough to fill YUV planes
    if (size < width * height * 3 / 2) {
        tjDestroy(handle);
        return 0;
    }

    // Assign data to YUV planes
    yuvPlanes[0] = data; // Y plane
    yuvPlanes[1] = data + width * height; // U plane
    yuvPlanes[2] = data + width * height * 5 / 4; // V plane

    // Set strides
    strides[0] = width;
    strides[1] = width / 2;
    strides[2] = width / 2;

    // Call the function-under-test
    int result = tj3CompressFromYUVPlanes8(handle, yuvPlanes, width, strides, height, &jpegBuf, &jpegSize);

    // Clean up
    tjFree(jpegBuf);
    tjDestroy(handle);

    return 0;
}