extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.dev/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
}

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Ensure size is not zero to avoid tjAlloc(0)
    if (size == 0) return 0;

    // Use the size of the data as the integer parameter for tjAlloc
    int allocSize = static_cast<int>(size);

    // Call the function-under-test
    unsigned char *allocatedMemory = tjAlloc(allocSize);

    // Check if the memory was allocated successfully
    if (allocatedMemory != nullptr) {
        // Use the allocated memory in some way, if necessary
        // ...

        // Free the allocated memory
        tjFree(allocatedMemory);
    }

    return 0;
}