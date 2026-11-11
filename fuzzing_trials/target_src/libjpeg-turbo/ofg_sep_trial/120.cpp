#include <cstdint> // Include for uint8_t
#include <cstddef> // Include for size_t

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Initialize variables
    tjhandle handle = tjInitTransform();
    tjtransform transform;
    size_t bufSize = 0;

    // Ensure that the handle is not NULL
    if (handle == NULL) {
        return 0;
    }

    // Initialize the tjtransform structure with some default values
    transform.op = TJXOP_NONE;
    transform.options = 0;
    transform.r.x = 0;
    transform.r.y = 0;
    transform.r.w = 0;
    transform.r.h = 0;
    transform.customFilter = NULL;

    // Call the function-under-test
    bufSize = tj3TransformBufSize(handle, &transform);

    // Clean up
    tjDestroy(handle);

    return 0;
}