#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Initialize the integer parameter with a non-zero value
    int initValue = 1;

    // Call the function-under-test
    tjhandle handle = tj3Init(initValue);

    // Check if the handle is valid and clean up if necessary
    if (handle != NULL) {
        tj3Destroy(handle);
    }

    return 0;
}