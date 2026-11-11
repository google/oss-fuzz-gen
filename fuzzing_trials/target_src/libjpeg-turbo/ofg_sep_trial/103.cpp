#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Initialize a variable to hold the return value of tj3Init
    tjhandle handle;

    // Define an integer parameter for tj3Init
    int initParam = 0; // You can try different values like 0, 1, -1, etc.

    // Call the function-under-test
    handle = tj3Init(initParam);

    // Ensure to clean up if tj3Init was successful
    if (handle != nullptr) {
        tj3Destroy(handle);
    }

    return 0;
}