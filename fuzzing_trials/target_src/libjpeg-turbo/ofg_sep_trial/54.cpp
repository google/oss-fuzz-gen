#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Failed to initialize, exit early
    }

    unsigned char *yuvPlanes[3] = {nullptr, nullptr, nullptr};
    int strides[3] = {0, 0, 0};
    int width = 1;  // Dummy initialization, will be set by tjDecompressHeader
    int height = 1; // Dummy initialization, will be set by tjDecompressHeader
    int subsamp, colorspace;

    // Attempt to read header to get image dimensions and subsampling
    if (tjDecompressHeader3(handle, data, size, &width, &height, &subsamp, &colorspace) == 0) {
        // Allocate memory for YUV planes
        for (int i = 0; i < 3; i++) {
            yuvPlanes[i] = new unsigned char[tjPlaneSizeYUV(i, width, strides[i], height, subsamp)];
        }

        // Decompress to YUV planes
        tjDecompressToYUVPlanes(handle, data, size, yuvPlanes, width, strides, height, 0);
    }

    // Clean up
    for (int i = 0; i < 3; i++) {
        delete[] yuvPlanes[i];
    }
    tjDestroy(handle);

    return 0;
}