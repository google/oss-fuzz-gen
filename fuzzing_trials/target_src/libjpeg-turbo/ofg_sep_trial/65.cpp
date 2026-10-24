#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitCompress();
    if (handle == nullptr) {
        return 0;
    }

    // Call the function-under-test
    char *errorStr = tjGetErrorStr2(handle);

    // Use the errorStr to avoid unused variable warning
    if (errorStr != nullptr) {
        // Perform any operation with errorStr if needed
    }

    // Clean up
    tjDestroy(handle);

    return 0;
}