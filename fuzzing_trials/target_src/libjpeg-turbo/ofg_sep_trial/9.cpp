#include <cstddef>
#include <cstdint>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0;
    }

    // Set up YUV planes
    const unsigned char *yuvPlanes[3];
    int strides[3];
    unsigned char *dstBuffer = nullptr;
    int width = 4;  // Example width
    int height = 4; // Example height
    int subsamp = TJSAMP_420; // Example subsampling
    int flags = 0; // No flags

    if (size < 3 * width * height) {
        tjDestroy(handle);
        return 0;
    }

    // Assigning data to YUV planes
    yuvPlanes[0] = data;
    yuvPlanes[1] = data + width * height;
    yuvPlanes[2] = data + 2 * width * height;

    // Set strides
    strides[0] = width;
    strides[1] = width / 2;
    strides[2] = width / 2;

    // Allocate destination buffer
    dstBuffer = new unsigned char[width * height * 3]; // RGB buffer

    // Call the function-under-test
    int result = tjDecodeYUVPlanes(handle, yuvPlanes, strides, subsamp, dstBuffer, width, 0, height, TJPF_RGB, flags);

    // Clean up
    delete[] dstBuffer;
    tjDestroy(handle);

    return 0;
}