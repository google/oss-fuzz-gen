#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Call the function-under-test
    char *errorStr = tjGetErrorStr();

    // Use the error string in some way to avoid compiler optimizations removing the call
    if (errorStr != nullptr) {
        // Print the error string to a volatile variable to prevent it being optimized away
        volatile char *volatileErrorStr = errorStr;
    }

    return 0;
}