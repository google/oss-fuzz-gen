#include <cstdint>
#include <cstdlib>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Initialize variables for the function-under-test
    tjhandle handle = tjInitDecompress();
    tjregion region;

    // Ensure the input size is sufficient to set the region values
    if (size < sizeof(int) * 4) {
        tjDestroy(handle);
        return 0;
    }

    // Set the region values using the input data
    region.x = static_cast<int>(data[0]);
    region.y = static_cast<int>(data[1]);
    region.w = static_cast<int>(data[2]);
    region.h = static_cast<int>(data[3]);

    // Call the function-under-test
    int result = tj3SetCroppingRegion(handle, region);

    // Clean up
    tjDestroy(handle);

    return 0;
}