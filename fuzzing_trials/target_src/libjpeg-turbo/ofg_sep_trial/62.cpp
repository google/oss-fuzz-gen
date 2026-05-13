#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Include this for memcpy

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    // Alternatively, you can use one of the other paths if needed:
    // #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    // #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Initialize tjhandle
    tjhandle handle = tjInitDecompress();
    if (handle == nullptr) {
        return 0; // Early exit if handle initialization fails
    }

    // Ensure the data is not NULL and size is greater than zero
    if (data == nullptr || size == 0) {
        tjDestroy(handle);
        return 0;
    }

    // Allocate memory for ICC profile
    unsigned char *iccProfile = (unsigned char *)malloc(size);
    if (iccProfile == nullptr) {
        tjDestroy(handle);
        return 0; // Early exit if memory allocation fails
    }

    // Copy data to iccProfile
    memcpy(iccProfile, data, size);

    // Call the function-under-test
    int result = tj3SetICCProfile(handle, iccProfile, size);

    // Clean up
    free(iccProfile);
    tjDestroy(handle);

    return 0;
}