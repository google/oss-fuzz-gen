#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Added for memcpy

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Allocate a buffer of the same size as the input data
    void *buffer = malloc(size);
    if (buffer == nullptr) {
        return 0; // If allocation fails, return immediately
    }

    // Copy the input data to the buffer
    memcpy(buffer, data, size);

    // Call the function-under-test
    tj3Free(buffer);

    // Free the allocated buffer
    free(buffer);

    return 0;
}