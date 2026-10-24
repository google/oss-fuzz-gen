#include <cstddef>
#include <cstdint>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    // Ensure the size is not zero to prevent tjAlloc from allocating zero bytes
    if (size == 0) {
        return 0;
    }

    // Convert size to an integer, ensuring it is within a reasonable range
    int allocSize = static_cast<int>(size % 1024) + 1; // Limit size to a maximum of 1024 bytes

    // Call the function-under-test
    unsigned char *allocatedMemory = tjAlloc(allocSize);

    // Check if the allocation was successful
    if (allocatedMemory != nullptr) {
        // Use the allocated memory in some way, if necessary
        // For fuzzing, we don't need to use it, just ensure it's not NULL

        // Free the allocated memory
        tjFree(allocatedMemory);
    }

    return 0;
}