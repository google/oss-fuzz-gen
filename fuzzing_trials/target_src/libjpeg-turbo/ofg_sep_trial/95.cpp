#include <cstddef>
#include <cstdint>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Call the function-under-test
    tjhandle handle = tjInitCompress();

    // Since tjInitCompress does not take any input parameters and returns a handle,
    // there's no direct way to fuzz it beyond calling it. We can check if the handle
    // is valid and then clean up by destroying the handle.
    if (handle != nullptr) {
        // Perform any additional operations if needed, such as compressing a sample image
        // using the handle, but since this task is only about calling tjInitCompress,
        // we are not doing further operations.

        // Cleanup: destroy the handle after use
        tjDestroy(handle);
    }

    return 0;
}