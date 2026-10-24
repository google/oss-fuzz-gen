#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Initialize a TurboJPEG decompressor handle
    tjhandle handle = tj3Init(TJINIT_DECOMPRESS);
    if (handle == NULL) {
        return 0;
    }

    // Ensure the data is not NULL and size is greater than 0
    if (data != NULL && size > 0) {
        // Call the function-under-test
        tj3DecompressHeader(handle, data, size);
    }

    // Clean up the TurboJPEG decompressor handle
    tj3Destroy(handle);

    return 0;
}