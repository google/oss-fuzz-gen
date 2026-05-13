#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, return early
    }

    // Allocate memory for YUV planes
    const int numPlanes = 3; // YUV has 3 planes
    unsigned char *yuvPlanes[numPlanes];
    int planeSizes[numPlanes];

    // For simplicity, assume a small image size for plane allocation
    int width = 16;
    int height = 16;
    int subsampling = TJSAMP_420;
    int stride = 0; // Assuming no specific stride requirement

    for (int i = 0; i < numPlanes; ++i) {
        planeSizes[i] = tjPlaneSizeYUV(i, width, stride, height, subsampling);
        yuvPlanes[i] = static_cast<unsigned char*>(malloc(planeSizes[i]));
        if (yuvPlanes[i] == nullptr) {
            // Clean up and return if allocation fails
            for (int j = 0; j < i; ++j) {
                free(yuvPlanes[j]);
            }
            tjDestroy(handle);
            return 0;
        }
    }

    // Call the function-under-test
    tj3DecompressToYUVPlanes8(handle, data, size, yuvPlanes, planeSizes);

    // Clean up
    for (int i = 0; i < numPlanes; ++i) {
        free(yuvPlanes[i]);
    }
    tjDestroy(handle);

    return 0;
}