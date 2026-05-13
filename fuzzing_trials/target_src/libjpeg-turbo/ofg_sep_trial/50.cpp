#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    // You can also include other paths if needed:
    // #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    // #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Initialize the TurboJPEG decompressor
    tjhandle handle = tjInitDecompress();
    
    // Check if the handle was successfully created
    if (handle == NULL) {
        return 0; // Exit if initialization failed
    }

    // Normally, you would proceed to use 'handle' to perform decompression
    // operations on 'data'. However, for this task, we are only focusing on
    // initializing the decompressor.

    // Clean up the TurboJPEG decompressor handle
    tjDestroy(handle);

    return 0;
}