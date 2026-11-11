#include <stdint.h>
#include <stddef.h>

extern "C" {
    // Include the correct header where lou_version is declared
    #include "/src/liblouis/liblouis/liblouis.h"
}

extern "C" int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Call the function-under-test
    const char *version = lou_version();

    // Use the version string in some way to prevent compiler optimizations from removing the call
    if (version != nullptr && size > 0) {
        // Perform a simple operation with the version string and input data
        size_t version_length = 0;
        while (version[version_length] != '\0') {
            version_length++;
        }

        // Check if the first byte of data matches the first character of the version string
        if (data[0] == version[0]) {
            // Do something trivial
            (void)(version_length);
        }
    }

    return 0;
}