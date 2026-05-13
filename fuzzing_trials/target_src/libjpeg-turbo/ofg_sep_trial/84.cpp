#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Initialize variables required for tjTransform
    tjhandle handle = tjInitTransform();
    if (handle == nullptr) {
        return 0;
    }

    // Ensure size is not zero to prevent invalid memory access
    if (size == 0) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for the destination image buffer
    unsigned char *dstBuffer = nullptr;
    unsigned long dstSize = 0;

    // Create a transform object
    tjtransform transform;
    std::memset(&transform, 0, sizeof(tjtransform)); // Initialize to zero

    // Set the transform options (e.g., no operation)
    transform.op = TJXOP_NONE;

    // Call the function-under-test
    int result = tjTransform(handle, data, (unsigned long)size, 1, &dstBuffer, &dstSize, &transform, 0);

    // Clean up
    if (dstBuffer != nullptr) {
        tjFree(dstBuffer);
    }
    tjDestroy(handle);

    return 0;
}