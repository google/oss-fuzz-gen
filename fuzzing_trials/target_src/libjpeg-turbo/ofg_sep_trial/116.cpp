#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitCompress();

    // Fuzz the function-under-test
    if (handle != NULL) {
        // Call the function-under-test
        tjDestroy(handle);
    }

    return 0;
}