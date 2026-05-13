#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    tjhandle handle = tj3Init(TJINIT_COMPRESS);  // Initialize a TurboJPEG handle for compression

    if (handle == NULL) {
        return 0;  // Exit if the handle initialization failed
    }

    // Call the function-under-test with the initialized handle
    int errorCode = tj3GetErrorCode(handle);

    // Use the errorCode in some way to prevent compiler optimizations from removing the call
    if (errorCode != 0) {
        // Handle the error code if necessary
    }

    tj3Destroy(handle);  // Clean up and destroy the TurboJPEG handle

    return 0;
}