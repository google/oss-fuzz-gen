#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Allocate memory for YUV planes
    const unsigned char *yuvPlanes[3];
    int strides[3];
    int width = 16;  // Example width
    int height = 16; // Example height

    // Ensure size is large enough for the YUV data
    if (size < static_cast<size_t>(width * height * 3 / 2)) {
        tjDestroy(handle);
        return 0;
    }

    // Assign data to YUV planes
    yuvPlanes[0] = data;
    yuvPlanes[1] = data + width * height;
    yuvPlanes[2] = data + width * height + (width / 2) * (height / 2);

    strides[0] = width;
    strides[1] = width / 2;
    strides[2] = width / 2;

    // Allocate memory for the output buffer
    unsigned char *dstBuf = (unsigned char *)malloc(width * height * 3);
    if (dstBuf == nullptr) {
        tjDestroy(handle);
        return 0;
    }

    // Call the function under test with the correct number of arguments
    int result = tjDecodeYUVPlanes(handle, yuvPlanes, strides, TJSAMP_420, dstBuf, width, width * tjPixelSize[TJPF_RGB], height, TJPF_RGB, 0);

    // Clean up
    free(dstBuf);
    tjDestroy(handle);

    return result;
}