#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for meaningful processing
    if (size < 10) {
        return 0;
    }

    // Call the function-under-test
    tjhandle handle = tjInitDecompress();
    
    // Check if the handle is valid
    if (handle == nullptr) {
        return 0;
    }

    // Cleanup: Destroy the handle after use
    tjDestroy(handle);

    return 0;
}