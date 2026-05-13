#include <stdint.h>
#include <stddef.h>

extern "C" {
    // Include the correct header for the function-under-test
    #include "/src/liblouis/liblouis/liblouis.h"
}

// Fuzzing harness for lou_version
extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *version = lou_version();

    // Optionally, you can use the version string in some way
    // For this example, we will just check if it's not null
    if (version != nullptr) {
        // Do something with the version string if needed
    }

    return 0;
}