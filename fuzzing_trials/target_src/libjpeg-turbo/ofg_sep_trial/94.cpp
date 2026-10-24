#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    tjhandle handle = nullptr;
    int errorCode = 0;

    // Create a TurboJPEG decompressor or compressor handle
    handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // If initialization fails, return immediately
    }

    // Call the function-under-test
    errorCode = tjGetErrorCode(handle);

    // Clean up and destroy the TurboJPEG handle
    tjDestroy(handle);

    return 0;
}