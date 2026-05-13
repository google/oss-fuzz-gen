#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Call the function-under-test
    tjhandle handle = tjInitCompress();

    // Check if the handle is valid
    if (handle != nullptr) {
        // Perform any additional operations needed for fuzzing
        // Since tjInitCompress doesn't take any parameters, there's nothing
        // more to do for this function in terms of fuzzing inputs.

        // Clean up and destroy the handle
        tjDestroy(handle);
    }

    return 0;
}