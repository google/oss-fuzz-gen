#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    tjhandle handle = tjInitCompress();  // Initialize a TurboJPEG compressor handle
    if (handle == nullptr) {
        return 0;  // If initialization fails, return early
    }

    // Call the function-under-test with the initialized handle
    char *errorStr = tjGetErrorStr2(handle);

    // Clean up the TurboJPEG handle
    tjDestroy(handle);

    return 0;
}