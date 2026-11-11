#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    tjhandle handle;
    tjregion region;

    // Initialize tjhandle
    handle = tj3Init(TJINIT_DECOMPRESS);
    if (handle == NULL) {
        return 0;
    }

    // Initialize tjregion with non-NULL values
    region.x = size > 0 ? data[0] % 256 : 0;
    region.y = size > 1 ? data[1] % 256 : 0;
    region.w = size > 2 ? data[2] % 256 : 1; // Width should be non-zero
    region.h = size > 3 ? data[3] % 256 : 1; // Height should be non-zero

    // Call the function-under-test
    tj3SetCroppingRegion(handle, region);

    // Clean up
    tj3Destroy(handle);

    return 0;
}